# cgumi

https://crates.io/crates/cgumi

cgumi is yet another crate for interacting with cgroupv2 (WIP). It focuses on serving apps for creating their own cgroupv2 hierarchies, instead of managing all cgroup nodes on one system.

There is no plan for legacy cgroupv1 support.

## Notes

Breaking changes may happen! And suggestions are very welcomed as current API design may be suboptimized.

`systemd` feature is enabled by default.

## Planned features

- [x] Create node
- [x] Move process to node
- [x] Delegate node (chown)
- [x] Get memory & io usage
- [x] Sudo + sh support
- [x] Systemd support
