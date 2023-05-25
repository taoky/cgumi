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

use cgumi::DelegateMode;
use nix::unistd::{close, Pid, Uid};

extern crate cgumi;

fn main() {
    // let ctl = cgumi::CgroupController::default();
    let ctl = cgumi::CgroupController::new(
        cgumi::CGROUPV2_DEFAULT_PATH,
        Some(Box::new(cgumi::utils::sudo_request_func)),
    );
    // Currently just create a new cgroup node under root
    let mut root = ctl.get_root_node().unwrap();
    let test_name = format!("test-node-{}", rand::random::<u32>());
    let test_node = ctl
        .create_from_node_path(&root, &PathBuf::from(test_name), false)
        .unwrap();
    test_node
        .delegate(
            Uid::current(),
            &[
                DelegateMode::DelegateNewSubtree,
                DelegateMode::DelegateProcs,
            ],
        )
        .unwrap();
    let inside_node = ctl
        .create_from_node_path(&test_node, &PathBuf::from("test-node-inside"), false)
        .unwrap();
    let parent_node = ctl
        .create_from_node_path(&test_node, &PathBuf::from("test-parent"), false)
        .unwrap();

    // Delegation
    parent_node
        .delegate(Uid::current(), &[DelegateMode::DelegateProcs])
        .unwrap();
    inside_node
        .delegate(Uid::current(), &[DelegateMode::DelegateProcs])
        .unwrap();
    parent_node.move_process(Pid::this()).unwrap();

    // Add memory control to the node
    test_node
        .adjust_subtree_controls(&[cgumi::SubtreeControl::Memory], &[])
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

    test_node.cleanup(&mut root).unwrap();
    test_node.destroy().unwrap();
}
