# cgumi

https://crates.io/crates/cgumi

cgumi is yet another crate for interacting with cgroupv2 (WIP). It focuses on serving apps for creating their own cgroupv2 hierarchies, instead of managing all cgroup nodes on one system.

There is no plan for legacy cgroupv1 support.

## Notes

Breaking changes may happen! And suggestions are very welcomed as current API design may be suboptimized.

**`systemd` feature is enabled by default**. To disable `systemd` feature (and thus avoiding installing `zbus`):

```
[dependencies]
cgumi = { version = "*", default-features = false }
```

## Planned features

- [x] Create node
- [x] Move process to node
- [x] Delegate node (chown)
- [x] Get memory & io usage
- [x] Sudo + sh support
- [x] Systemd support

## Running tests

Some tests run only in root, and some others run only in non-root env.

```sh
# both are necessary to run all tests
cargo test
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' cargo test
```

And also, you can run tests with `--nocapture` to see more details. `RUST_LOG` is also available.

```sh
RUST_LOG=debug cargo test -- --nocapture
```
