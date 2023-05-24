// Execute a program, and print out its maximum mem usage after it exits.
// It works by:
// 1. Create an empty cgroup node (call it as NODE1 here)
// 2. As limited by "no internal processes" rule, an extra empty cgroup node (called as NODE11) should be created inside
// 3. Add "memory" subtree control to NODE1
// 4. Fork process, and before exec(), put the process into NODE11 (UNSAFE!)
// 5. After wait() done, the parent gathers the memory usage of NODE11, and print it out.
// 6. Remove NODE11 and NODE1

fn main() {

}