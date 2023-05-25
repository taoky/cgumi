// Execute a program, and print out its maximum mem usage after it exits.
// It works by:
// 1. Create an empty cgroup node (call it as NODE1 here)
// 2. As limited by "no internal processes" rule[^1], an extra empty cgroup node (called as NODE11) should be created inside
// 3. Add "memory" subtree control to NODE1 (and thus NODE11 gets memory control!)
// 4. Fork process, and before exec(), put the process into NODE11 (UNSAFE!)
// 5. After wait() done, the parent gathers the memory usage of NODE11, and print it out.
// 6. Remove NODE11 and NODE1

// [^1]: Extra empty node is not necessary if the empty node created before has already got memory control.
//       However, you may find it required when using delegated controllers and you need to measure multiple processes
//       Thus in this example we still create an extra empty node.

use std::{os::unix::process::CommandExt, path::PathBuf};

use nix::unistd::close;

extern crate cgumi;

fn main() {
    let ctl = cgumi::CgroupController::default();
    // Currently just create a new cgroup node under root
    let mut root = ctl.get_root_node().unwrap();
    let test_name = format!("test-node-{}", rand::random::<u32>());
    let mut test_node = ctl
        .create_from_node_path(&root, &PathBuf::from(test_name), false)
        .unwrap();
    let test_node2 = ctl
        .create_from_node_path(&test_node, &PathBuf::from("test-node-inside"), false)
        .unwrap();

    // Add memory control to the node
    test_node
        .adjust_subtree_controls(&[cgumi::SubtreeControl::Memory], &[])
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

    test_node.cleanup(&mut root).unwrap();
    test_node.destroy().unwrap();
}
