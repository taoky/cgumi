// Execute a program, and print out its maximum mem usage after it exits.
// Uses delegation and sudo
// It works by:
// 1. Create an empty cgroup node (call it as NODE1 here) and delegate to current user
// 2. As limited by "no internal processes" rule[^1], an extra empty cgroup node (called as NODE11) should be created inside
// 3. Another empty cgroup node (called as NODE12) is created inside NODE1, to store current program PID
// 4. Add "memory" subtree control to NODE1 (and thus NODE11 gets memory control!)
// 5. Fork process, and before exec(), move the new process (from NODE12) into NODE11 (UNSAFE!)
// 6. After wait() done, the parent gathers the memory usage of NODE11, and print it out.
// 7. Remove NODE12, NODE11 and NODE1

use std::{os::unix::process::CommandExt, path::PathBuf};

use log::info;
use nix::unistd::{close, Pid};

extern crate cgumi;

fn main() {
    env_logger::init();

    let ctl = cgumi::CgroupController::default();
    let mut node = ctl.create_systemd_cgroup("cgumi-test").unwrap();
    info!("Created node: {}", node.path().display());

    let test_node2 = ctl
        .create_from_node_path(&node, &PathBuf::from("test-node-inside"), false)
        .unwrap();
    let mut test_hostprog = ctl
        .create_from_node_path(&node, &PathBuf::from("test-host"), false)
        .unwrap();

    test_hostprog.move_process(Pid::this()).unwrap();

    // Add memory control to the node
    node.adjust_subtree_controls(&[cgumi::SubtreeControl::Memory], &[])
        .unwrap();

    // Create example app
    let mut cmd = std::process::Command::new("python3");
    let cmd = cmd.args(["-c", "x = [0] * 1024 * 1024"]);

    // Preparing for pre_exec
    let procs_fd = cgumi::utils::get_cgroup_proc_fd(&test_node2).unwrap();

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

    let peak = test_node2.get_memory_peak().unwrap();

    println!("Peak mem usage: {} Bytes", peak);
}
