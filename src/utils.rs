use nix::{
    fcntl::{open, OFlag},
    sys::stat::Mode,
    unistd::{close, write},
};

use crate::{nix_to_io_error, CgroupNode};

// An u32 to bytes utility function for limited env
fn u32_to_bytes(x: u32, buf: &mut [u8]) -> usize {
    if x == 0 {
        buf[0] = b'0';
        1
    } else {
        let mut i = 0;
        let mut x = x;
        while x > 0 {
            buf[i] = (x % 10) as u8 + b'0';
            x /= 10;
            i += 1;
        }
        // reverse
        let mut j = 0;
        while j < i / 2 {
            buf.swap(j, i - j - 1);
            j += 1;
        }
        i
    }
}

// This utility function does not do heap memory allocation
// And thus safe to use inside pre_exec
pub fn add_self_to_proc(fd: i32, pid: u32) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 32];
    let len = u32_to_bytes(pid, &mut buf);
    write(fd, &buf.as_slice()[..len])?;
    close(fd)?;
    Ok(())
}

pub fn get_cgroup_proc_fd(node: &CgroupNode) -> Result<i32, std::io::Error> {
    open(
        node.path.join("cgroup.procs").as_os_str(),
        OFlag::O_WRONLY,
        Mode::empty(),
    )
    .map_err(nix_to_io_error)
}
