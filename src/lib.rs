use nix::unistd::{chown, Pid, Uid};
use std::{num::ParseIntError, path::PathBuf, str::FromStr};
use thiserror::Error;

#[macro_use]
extern crate log;

const DEFAULT_CGROUPV2_PATH: &str = "/sys/fs/cgroup/";

#[derive(Error, Debug)]
pub enum CgroupError {
    #[error("error when creating cgroup node: {0}")]
    CreateNodeError(std::io::Error),
    #[error("error when reading cgroup file: {0}")]
    ReadFileError(std::io::Error),
    #[error("error when removing cgroup node: {0}")]
    RemoveNodeError(std::io::Error),
    #[error("error when writing to cgroup file: {0}")]
    WriteFileError(std::io::Error),
    #[error("error when delegating (chowning): {0}")]
    DelegateError(std::io::Error),
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
}

#[derive(PartialEq, Debug)]
pub enum SubtreeControl {
    Cpuset,
    Cpu,
    Io,
    Memory,
    Hugetlb,
    Pids,
    Rdma,
    Misc,
    Others(String),
}

impl std::fmt::Display for SubtreeControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubtreeControl::Cpuset => write!(f, "cpuset"),
            SubtreeControl::Cpu => write!(f, "cpu"),
            SubtreeControl::Io => write!(f, "io"),
            SubtreeControl::Memory => write!(f, "memory"),
            SubtreeControl::Hugetlb => write!(f, "hugetlb"),
            SubtreeControl::Pids => write!(f, "pids"),
            SubtreeControl::Rdma => write!(f, "rdma"),
            SubtreeControl::Misc => write!(f, "misc"),
            SubtreeControl::Others(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for SubtreeControl {
    type Err = CgroupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cpuset" => Ok(SubtreeControl::Cpuset),
            "cpu" => Ok(SubtreeControl::Cpu),
            "io" => Ok(SubtreeControl::Io),
            "memory" => Ok(SubtreeControl::Memory),
            "hugetlb" => Ok(SubtreeControl::Hugetlb),
            "pids" => Ok(SubtreeControl::Pids),
            "rdma" => Ok(SubtreeControl::Rdma),
            "misc" => Ok(SubtreeControl::Misc),
            _ => Ok(SubtreeControl::Others(s.into())),
        }
    }
}

pub enum DelegateMode {
    DelegateNewSubtree,
    DelegateProcs,
    DelegateSubtreeControl,
    DelegateThreads,
}

fn nix_to_io_error(nix_error: nix::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(nix_error as i32)
}

#[derive(Debug, Default, Clone)]
pub struct IOStat {
    pub device: String,
    pub rbytes: u64,
    pub wbytes: u64,
    pub rios: u64,
    pub wios: u64,
    pub dbytes: u64,
    pub dios: u64,
}

#[derive(Debug)]
pub struct CgroupController {
    root: PathBuf,
}

impl Default for CgroupController {
    fn default() -> Self {
        Self {
            root: DEFAULT_CGROUPV2_PATH.into(),
        }
    }
}

impl CgroupController {
    pub fn new(root: &str) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    pub fn create_from_path(
        &self,
        name: &PathBuf,
        allow_exists: bool,
    ) -> Result<CgroupNode, CgroupError> {
        let mut path = PathBuf::from(&self.root);
        path.push(name);
        CgroupNode::create(&path, allow_exists)
    }

    pub fn get_from_current(&self) -> Result<CgroupNode, CgroupError> {
        // Get cgroup path from /proc/self/cgroup
        let cgroup_file_contents =
            std::fs::read_to_string("/proc/self/cgroup").map_err(CgroupError::ReadFileError)?;

        let hierarchy_list: Vec<_> = cgroup_file_contents.trim().splitn(3, ':').collect();

        if hierarchy_list.len() != 3 {
            return Err(CgroupError::ReadFileError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid cgroup file",
            )));
        }

        let relative_cgroup = hierarchy_list[2].trim_start_matches('/');

        let mut path = PathBuf::from(&self.root);
        path.push(relative_cgroup);

        debug!("cgroup path: {:?}", path);

        CgroupNode::create(&path, true)
    }

    pub fn create_from_node_path(
        &self,
        node: &CgroupNode,
        name: &PathBuf,
        allow_exists: bool,
    ) -> Result<CgroupNode, CgroupError> {
        if !node.path.starts_with(&self.root) {
            return Err(CgroupError::CreateNodeError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "node path is not under cgroup root",
            )));
        }
        self.create_from_path(name, allow_exists)
    }

    pub fn get_root_node(&self) -> Result<CgroupNode, CgroupError> {
        CgroupNode::create(&self.root, true)
    }
}

#[derive(Debug)]
pub struct CgroupNode {
    path: PathBuf,
}

impl CgroupNode {
    pub fn create(path: &PathBuf, allow_exists: bool) -> Result<CgroupNode, CgroupError> {
        if path.exists() {
            if !allow_exists {
                return Err(CgroupError::CreateNodeError(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "cgroup node already exists",
                )));
            } else {
                return Ok(CgroupNode { path: path.clone() });
            }
        }

        std::fs::create_dir_all(path).map_err(CgroupError::CreateNodeError)?;

        Ok(CgroupNode { path: path.clone() })
    }

    pub fn children(&self) -> Result<Vec<CgroupNode>, CgroupError> {
        let mut res = Vec::new();
        for entry in self.path.read_dir().map_err(CgroupError::ReadFileError)? {
            let entry = entry.map_err(CgroupError::ReadFileError)?;
            if entry
                .metadata()
                .map_err(CgroupError::ReadFileError)?
                .is_dir()
            {
                res.push(CgroupNode::create(&entry.path(), true)?);
            }
        }
        Ok(res)
    }

    pub fn move_process(&mut self, pid: Pid) -> Result<(), CgroupError> {
        let pid_str = pid.to_string();
        std::fs::write(self.path.join("cgroup.procs"), pid_str).map_err(CgroupError::WriteFileError)
    }

    pub fn cleanup(&self, dst_node: &mut CgroupNode) -> Result<(), CgroupError> {
        if dst_node.path.starts_with(&self.path) {
            return Err(CgroupError::InvalidOperation(
                "cleanup dst node is under src node".into(),
            ));
        }
        for child in self.children()? {
            child.cleanup(dst_node)?;
        }
        let pid_list = self.get_pid_list()?;
        for pid in pid_list {
            dst_node.move_process(pid)?;
        }
        Ok(())
    }

    pub fn destroy(self) -> Result<(), CgroupError> {
        for child in self.children()? {
            child.destroy()?;
        }
        std::fs::remove_dir(self.path).map_err(CgroupError::RemoveNodeError)
    }

    pub fn get_pid_list(&self) -> Result<Vec<Pid>, CgroupError> {
        // read cgroup.procs file
        let pid_list_contents = std::fs::read_to_string(self.path.join("cgroup.procs"))
            .map_err(CgroupError::ReadFileError)?;
        let pid_list: Result<Vec<Pid>, _> = pid_list_contents
            .trim_end()
            .split('\n')
            .filter(|pid| !pid.is_empty())
            .map(|pid| -> Result<Pid, ParseIntError> { Ok(Pid::from_raw(pid.trim().parse()?)) })
            .collect();
        pid_list.map_err(|e| {
            CgroupError::ReadFileError(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
    }

    pub fn get_subtree_controls(&self) -> Result<Vec<SubtreeControl>, CgroupError> {
        let subtree_control_contents =
            std::fs::read_to_string(self.path.join("cgroup.subtree_control"))
                .map_err(CgroupError::ReadFileError)?;
        subtree_control_contents
            .trim_end()
            .split(' ')
            .filter(|control| !control.is_empty())
            .map(|control| control.parse())
            .collect()
    }

    pub fn adjust_subtree_controls(
        &mut self,
        add_list: &[SubtreeControl],
        remove_list: &[SubtreeControl],
    ) -> Result<(), CgroupError> {
        let mut control_str = String::new();
        for control in add_list {
            control_str.push('+');
            control_str.push_str(&control.to_string());
            control_str.push(' ');
        }
        for control in remove_list {
            control_str.push('-');
            control_str.push_str(&control.to_string());
            control_str.push(' ');
        }
        std::fs::write(self.path.join("cgroup.subtree_control"), control_str)
            .map_err(CgroupError::WriteFileError)
    }

    pub fn delegate(&mut self, uid: Uid, modes: &[DelegateMode]) -> Result<(), CgroupError> {
        for mode in modes {
            let file = match mode {
                DelegateMode::DelegateNewSubtree => ".",
                DelegateMode::DelegateProcs => "cgroup.procs",
                DelegateMode::DelegateSubtreeControl => "cgroup.subtree_control",
                DelegateMode::DelegateThreads => "cgroup.threads",
            };
            let path = self.path.join(file);

            chown(&path, Some(uid), None)
                .map_err(nix_to_io_error)
                .map_err(CgroupError::DelegateError)?;
        }
        Ok(())
    }

    pub fn get_memory_peak(&self) -> Result<u64, CgroupError> {
        let contents = std::fs::read_to_string(self.path.join("memory.peak"))
            .map_err(CgroupError::ReadFileError)?;
        contents.trim_end().parse().map_err(|e| {
            CgroupError::ReadFileError(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
    }

    pub fn get_io_stat(&self) -> Result<Vec<IOStat>, CgroupError> {
        macro_rules! invalid_format_error {
            () => {
                CgroupError::ReadFileError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid io.stat format",
                ))
            };
            ($e: expr) => {
                CgroupError::ReadFileError(std::io::Error::new(std::io::ErrorKind::InvalidData, $e))
            };
        }
        let contents = std::fs::read_to_string(self.path.join("io.stat"))
            .map_err(CgroupError::ReadFileError)?;
        let mut stats = Vec::new();
        for line in contents.trim_end().split('\n') {
            let mut fields = line.split_whitespace();
            let mut stat = IOStat::default();
            let device = fields.next().ok_or_else(|| invalid_format_error!())?;
            stat.device = device.to_string();
            for field in fields {
                let parts = field
                    .split_once('=')
                    .ok_or_else(|| invalid_format_error!())?;
                macro_rules! parse_field {
                    () => {
                        parts.1.parse().map_err(|e| invalid_format_error!(e))?
                    };
                }
                match parts.0 {
                    "rbytes" => stat.rbytes = parse_field!(),
                    "wbytes" => stat.wbytes = parse_field!(),
                    "rios" => stat.rios = parse_field!(),
                    "wios" => stat.wios = parse_field!(),
                    "dbytes" => stat.dbytes = parse_field!(),
                    "dios" => stat.dios = parse_field!(),
                    _ => return Err(invalid_format_error!()),
                }
            }
            stats.push(stat);
        }
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use rand;
    use test_log::test;

    fn is_root() -> bool {
        Uid::current().is_root()
    }

    // it could be better if Rust supports runtime conditional test
    macro_rules! root_only {
        () => {
            if !is_root() {
                warn!("Not running as root, skipping");
                return;
            }
        };
    }

    #[test]
    fn get_current_node_pid() {
        let ctl = CgroupController::default();
        let node = ctl.get_from_current().unwrap();
        let pid_list = node.get_pid_list().unwrap();
        assert!(pid_list.contains(&Pid::this()));
    }

    #[test]
    fn get_root_children() {
        let ctl = CgroupController::default();
        let root = ctl.get_root_node().unwrap();
        let children = root.children().unwrap();
        for child in children {
            if child.path.ends_with("system.slice") {
                return;
            }
        }
        assert!(false)
    }

    #[test]
    fn get_root_subtree_control() {
        let ctl = CgroupController::default();
        let root = ctl.get_root_node().unwrap();
        let controls = root.get_subtree_controls().unwrap();
        assert!(controls.contains(&SubtreeControl::Pids));
    }

    #[test]
    fn get_memory_peak() {
        let ctl = CgroupController::default();
        let node = ctl.get_from_current().unwrap();
        let peak = node.get_memory_peak().unwrap();
        assert!(peak > 0);
    }

    #[test]
    fn get_io_stat() {
        let ctl = CgroupController::default();
        let node = ctl.get_root_node().unwrap();
        let stats = node.get_io_stat().unwrap();
        assert!(stats.len() > 0);
    }

    fn create_test_node_on_root_node(ctl: &CgroupController) -> CgroupNode {
        // randomly generate a test node
        let test_node_name = format!("test_node_{}", rand::random::<u64>());
        let root = ctl.get_root_node().unwrap();
        let test_node = ctl
            .create_from_node_path(&root, &PathBuf::from(test_node_name), true)
            .unwrap();
        test_node
    }

    fn cleanup_node(ctl: &CgroupController, node: CgroupNode) {
        let mut root = ctl.get_root_node().unwrap();
        node.cleanup(&mut root).unwrap();
        node.destroy().unwrap();
    }

    #[test]
    fn create_new_node() {
        root_only!();
        let ctl = CgroupController::default();
        let test_node = create_test_node_on_root_node(&ctl);

        // cleanup
        cleanup_node(&ctl, test_node);
    }

    #[test]
    fn delegation_test() {
        root_only!();
        let ctl = CgroupController::default();
        let mut test_node = create_test_node_on_root_node(&ctl);

        test_node
            .delegate(
                Uid::from_raw(1000),
                &[
                    DelegateMode::DelegateNewSubtree,
                    DelegateMode::DelegateProcs,
                    DelegateMode::DelegateSubtreeControl,
                ],
            )
            .unwrap();
        // cleanup
        cleanup_node(&ctl, test_node);
    }

    #[test]
    fn subtree_test() {
        root_only!();
        let ctl = CgroupController::default();
        let mut test_node = create_test_node_on_root_node(&ctl);

        let subtree = test_node.get_subtree_controls().unwrap();
        debug!("{:?}", subtree);
        assert!(subtree.len() == 0);
        test_node
            .adjust_subtree_controls(
                &[
                    SubtreeControl::Cpu,
                    SubtreeControl::Memory,
                    SubtreeControl::Io,
                ],
                &[],
            )
            .unwrap();
        let subtree = test_node.get_subtree_controls().unwrap();
        assert!(subtree.len() == 3);
        test_node
            .adjust_subtree_controls(
                &[],
                &[
                    SubtreeControl::Cpu,
                    SubtreeControl::Memory,
                    SubtreeControl::Io,
                ],
            )
            .unwrap();
        let subtree = test_node.get_subtree_controls().unwrap();
        assert!(subtree.len() == 0);

        cleanup_node(&ctl, test_node);
    }

    #[test]
    fn move_pid_test() {
        root_only!();
        // create a testing process that sleeps 10s
        let mut handle = Command::new("sleep").arg("10").spawn().unwrap();
        let pid = Pid::from_raw(handle.id() as i32);

        let ctl = CgroupController::default();
        let mut test_node = create_test_node_on_root_node(&ctl);

        test_node.move_process(pid).unwrap();
        let pid_list = test_node.get_pid_list().unwrap();
        assert!(pid_list.contains(&pid));

        // test if cleanup succeeds
        cleanup_node(&ctl, test_node);

        // kill the testing process
        handle.kill().unwrap();
    }
}
