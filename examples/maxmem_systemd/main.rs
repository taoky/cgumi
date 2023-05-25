// Execute a program, and print out its maximum mem usage after it exits.
// Uses systemd scope
// (Modified from maxmem_delegation)

use std::{os::unix::process::CommandExt, path::PathBuf};

use log::info;
use nix::unistd::{close, Pid};

extern crate cgumi;

fn main() {
    env_logger::init();

    let ctl = cgumi::CgroupController::default();
    let node = ctl.create_systemd_cgroup("cgumi-test").unwrap();
    info!("Created node: {}", node.path().display());

    let inside_node = ctl
        .create_from_node_path(&node, &PathBuf::from("test-node-inside"), false)
        .unwrap();
    let parent_node = ctl
        .create_from_node_path(&node, &PathBuf::from("test-parent"), false)
        .unwrap();

    parent_node.move_process(Pid::this()).unwrap();

    // Add memory control to the node
    node.adjust_subtree_controls(&[cgumi::SubtreeControl::Memory], &[])
        .unwrap();

    // Create example app
    let mut cmd = std::process::Command::new("python3");
    let cmd = cmd.args(["-c", "x = [0] * 1024 * 1024"]);

    // Preparing for pre_exec
    let procs_fd = cgumi::utils::get_cgroup_proc_fd(&inside_node).unwrap();

    unsafe {
        cmd.pre_exec(move || cgumi::utils::add_self_to_proc(procs_fd, std::process::id()));
    }

    let res = cmd.spawn().unwrap().wait().unwrap();
    let _ = close(procs_fd);

    if !res.success() {
        match res.code() {
            Some(code) => {
                eprintln!("Command exited with non-zero status code: {}", code)
            }
            None => eprintln!("Command terminated by a signal"),
        }
    }

    let peak = inside_node.get_memory_peak().unwrap();

    println!("Peak mem usage: {} Bytes", peak);
}
