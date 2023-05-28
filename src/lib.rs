use nix::unistd::{chown, Pid, Uid};
use shell_escape::unix::escape;
use std::{num::ParseIntError, path::PathBuf, str::FromStr};
use thiserror::Error;
use trait_set::trait_set;

#[cfg(feature = "systemd")]
use zbus::blocking::Connection;

#[macro_use]
extern crate log;

pub mod utils;

#[cfg(feature = "systemd")]
mod zbus_systemd;

/// The default path of Cgroupv2 on most Linux systems.
/// Systemd hybrid cgroup mode is NOT tested and this path is not applicable in this case.
pub const CGROUPV2_DEFAULT_PATH: &str = "/sys/fs/cgroup/";

/// All functions in cgumi use `CgroupError` as the returned error type.
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
    #[error("error when requesting user: {0}")]
    RequestUserError(std::io::Error),
    #[cfg(feature = "systemd")]
    #[error("error when using systemd: {0}")]
    SystemdError(zbus::Error),
}

/// Available values for `cgroup.subtree_control`.
/// `SubtreeControl::Others(String)` is for new, unknown control type.
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

/// Different value in `DelegateMode` indicates different file to be chown(2)ed.
pub enum DelegateMode {
    DelegateNewSubtree,
    DelegateProcs,
    DelegateSubtreeControl,
    DelegateThreads,
}

fn nix_to_io_error(nix_error: nix::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(nix_error as i32)
}

/// `IOStat` contains information in every line of `io.stat`.
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

/// Privilege operations that may need to be elevated to do.
/// This enum helps request helper function to show proper prompts to user.
#[derive(Debug, PartialEq)]
pub enum PrivilegeOpType {
    CreateNode,
    DelegateNode,
    RemoveNode,
    MoveProcess,
    AdjustSubtreeControls,
}

trait_set! {
    pub trait Func = Fn(&PrivilegeOpType, &str) -> Result<(), std::io::Error>;
}

/// `CgroupController` is the main component in cgumi, and it should always be created first.
/// All `CgroupNode` should be created by `CgroupController`.
pub struct CgroupController<F>
where
    F: Func,
{
    root: PathBuf,
    request_func: Option<Box<F>>,
}

impl<F> std::fmt::Debug for CgroupController<F>
where
    F: Func,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CgroupController")
            .field("root", &self.root)
            .field("is request_func available", &self.request_func.is_some())
            .finish()
    }
}

impl<F> Default for CgroupController<F>
where
    F: Func,
{
    fn default() -> Self {
        Self {
            root: CGROUPV2_DEFAULT_PATH.into(),
            request_func: None,
        }
    }
}

impl<F> CgroupController<F>
where
    F: Func,
{
    /// `root` is the cgroupv2 mountpoint, and `request_func` is an optional
    /// function that prompts users to run commands in root permission.
    pub fn new(root: &str, request_func: Option<F>) -> Self {
        Self {
            root: root.into(),
            request_func: request_func.map(Box::new),
        }
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    /// Create a `CgroupNode` from a relative path (`name`).
    pub fn create_from_path(
        &self,
        name: &PathBuf,
        allow_exists: bool,
    ) -> Result<CgroupNode<F>, CgroupError> {
        let path = PathBuf::from(&self.root).join(name);
        let res = CgroupNode::create(&path, allow_exists, self.request_func.as_deref());
        match res {
            Ok(res) => Ok(res),
            Err(CgroupError::CreateNodeError(e)) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    if let Some(request_func) = &self.request_func {
                        let command = if allow_exists {
                            format!("mkdir -p {}", escape(path.to_string_lossy()))
                        } else {
                            format!("mkdir {}", escape(path.to_string_lossy()))
                        };
                        request_func(&PrivilegeOpType::CreateNode, &command)
                            .map_err(CgroupError::RequestUserError)?;
                        CgroupNode::create(&path, true, self.request_func.as_deref())
                    } else {
                        Err(CgroupError::CreateNodeError(e))
                    }
                } else {
                    Err(CgroupError::CreateNodeError(e))
                }
            }
            _ => unreachable!(),
        }
    }

    /// Get the `CgroupNode` from what current program is in.
    pub fn get_from_current(&self) -> Result<CgroupNode<F>, CgroupError> {
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

        let path = PathBuf::from(&self.root).join(relative_cgroup);

        debug!("cgroup path: {:?}", path);

        CgroupNode::create(&path, true, self.request_func.as_deref())
    }

    /// Create a `CgroupNode` from a `node` and a `name` relative to the node.
    pub fn create_from_node_path(
        &self,
        node: &CgroupNode<F>,
        name: &PathBuf,
        allow_exists: bool,
    ) -> Result<CgroupNode<F>, CgroupError> {
        if !node.path.starts_with(&self.root) {
            return Err(CgroupError::CreateNodeError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "node path is not under cgroup root",
            )));
        }
        self.create_from_path(&node.path.join(name), allow_exists)
    }

    /// Get the root as a `CgroupNode`.
    pub fn get_root_node(&self) -> Result<CgroupNode<F>, CgroupError> {
        CgroupNode::create(&self.root, true, self.request_func.as_deref())
    }

    /// Create a systemd scope, and therefore get a cgroup node from that.
    #[cfg(feature = "systemd")]
    pub fn create_systemd_cgroup(&self, name: &str) -> Result<CgroupNode<F>, CgroupError> {
        let connection = Connection::session().map_err(CgroupError::SystemdError)?;
        let systemd_manager = zbus_systemd::ManagerProxyBlocking::new(&connection)
            .map_err(CgroupError::SystemdError)?;
        let pids = [Pid::this().as_raw() as u32];
        let scope_name = format!("{}.scope", name);

        let _err = systemd_manager.reset_failed_unit(&scope_name);

        let removed_jobs = systemd_manager
            .receive_job_removed()
            .map_err(CgroupError::SystemdError)?;

        let job = systemd_manager
            .start_transient_unit(&scope_name, "replace", &[("PIDs", pids[..].into())], &[])
            .map_err(CgroupError::SystemdError)?;

        for signal in removed_jobs {
            let args = signal.args().map_err(CgroupError::SystemdError)?;
            if args.job == job.as_ref() {
                break;
            }
        }

        let scope_dbus_path = systemd_manager
            .get_unit(&scope_name)
            .map_err(CgroupError::SystemdError)?;
        let systemd_scope = zbus_systemd::ScopeProxyBlocking::builder(&connection)
            .path(scope_dbus_path)
            .map_err(CgroupError::SystemdError)?
            .build()
            .map_err(CgroupError::SystemdError)?;
        let cgroup_path = systemd_scope
            .control_group()
            .map_err(CgroupError::SystemdError)?;
        let cgroup_path = cgroup_path.trim_start_matches('/');
        let cgroup_full_path = PathBuf::from(&self.root).join(cgroup_path);
        debug!("cgroup path: {:?}", cgroup_full_path);
        let node = CgroupNode::create(&cgroup_full_path, true, None)?;
        Ok(node)
    }
}

/// `CgroupNode` is created by `CgroupController`,
/// and operations other than creation is implemented in `CgroupNode`.
pub struct CgroupNode<'a, F>
where
    F: Func,
{
    path: PathBuf,
    request_func: Option<&'a F>,
}

impl<F> std::fmt::Debug for CgroupNode<'_, F> where F: Func {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CgroupNode")
            .field("path", &self.path)
            .field("is request_func available", &self.request_func.is_some())
            .finish()
    }
}

impl<F> CgroupNode<'_, F> where F: Func {
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub(crate) fn create<'a>(
        path: &PathBuf,
        allow_exists: bool,
        request_func: Option<&'a F>,
    ) -> Result<CgroupNode<'a, F>, CgroupError> {
        if path.exists() {
            if !allow_exists {
                return Err(CgroupError::CreateNodeError(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "cgroup node already exists",
                )));
            } else {
                return Ok(CgroupNode {
                    path: path.clone(),
                    request_func,
                });
            }
        }

        std::fs::create_dir_all(path).map_err(CgroupError::CreateNodeError)?;

        Ok(CgroupNode {
            path: path.clone(),
            request_func,
        })
    }

    /// Get children nodes
    pub fn children(&self) -> Result<Vec<CgroupNode<F>>, CgroupError> {
        let mut res = Vec::new();
        for entry in self.path.read_dir().map_err(CgroupError::ReadFileError)? {
            let entry = entry.map_err(CgroupError::ReadFileError)?;
            if entry
                .metadata()
                .map_err(CgroupError::ReadFileError)?
                .is_dir()
            {
                res.push(CgroupNode::create(&entry.path(), true, self.request_func)?);
            }
        }
        Ok(res)
    }

    /// Move processes from other cgroup nodes to this.
    /// You don't need to know where the original node pid is in (and this is how cgroupv2 works).
    /// Note that we call it "move", not "add", as EVERY process is in cgroupv2.
    pub fn move_process(&self, pid: Pid) -> Result<(), CgroupError> {
        let pid_str = pid.to_string();
        let procs_path = self.path.join("cgroup.procs");
        let res = std::fs::write(&procs_path, &pid_str);
        match res {
            Ok(_) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => {
                    if let Some(request_func) = self.request_func {
                        Ok(request_func(
                            &PrivilegeOpType::MoveProcess,
                            format!(
                                "echo {} > {}",
                                escape(pid_str.into()),
                                escape(procs_path.to_string_lossy())
                            )
                            .as_str(),
                        )
                        .map_err(CgroupError::RequestUserError)?)
                    } else {
                        Err(CgroupError::WriteFileError(e))
                    }
                }
                _ => Err(CgroupError::WriteFileError(e)),
            },
        }
    }

    /// `cleanup()` tries moving processes inside node to other ones.
    /// It is executed recursively.
    pub fn cleanup(&self, dst_node: &CgroupNode<F>) -> Result<(), CgroupError> {
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

    /// `destroy()` tries removing the cgroup node.
    /// It is executed recursively.
    /// Please note that you need to handle the invalidation of existing nodes yourself, like:
    ///
    /// ```ignore
    /// let node1 = ...
    /// let node2 = ctl.create_from_node_path(&node1, &PathBuf::from("test"), false);
    /// node1.destroy();
    /// // This will NOT cause compile error, but node2 is invalid now.
    /// // You need to identify this yourself.
    /// ```
    pub fn destroy(self) -> Result<(), CgroupError> {
        for child in self.children()? {
            child.destroy()?;
        }
        let res = std::fs::remove_dir(&self.path);
        match res {
            Ok(_) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => {
                    if let Some(request_func) = self.request_func {
                        Ok(request_func(
                            &PrivilegeOpType::RemoveNode,
                            format!("rmdir {}", escape(self.path.to_string_lossy())).as_str(),
                        )
                        .map_err(CgroupError::RequestUserError)?)
                    } else {
                        Err(CgroupError::RemoveNodeError(e))
                    }
                }
                _ => Err(CgroupError::RemoveNodeError(e)),
            },
        }
    }

    /// Parse and get process PIDs inside node by reading `cgroup.procs`.
    /// It is NOT recursively executed.
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

    /// Get subtree controls information from current node.
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

    /// Modify subtree controls in current node.
    /// Note that, due to "no internal processes" rule, unless you are operating a root node,
    /// a node cannot have both subtree controls and PIDs inside.
    pub fn adjust_subtree_controls(
        &self,
        add_list: &[SubtreeControl],
        remove_list: &[SubtreeControl],
    ) -> Result<(), CgroupError> {
        let mut control_str = String::new();
        let subtree_path = self.path.join("cgroup.subtree_control");
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
        let res = std::fs::write(&subtree_path, &control_str);
        match res {
            Ok(_) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => {
                    if let Some(request_func) = self.request_func {
                        Ok(request_func(
                            &PrivilegeOpType::AdjustSubtreeControls,
                            format!(
                                "echo {} > {}",
                                escape(control_str.into()),
                                escape(subtree_path.to_string_lossy())
                            )
                            .as_str(),
                        )
                        .map_err(CgroupError::RequestUserError)?)
                    } else {
                        Err(CgroupError::WriteFileError(e))
                    }
                }
                _ => Err(CgroupError::WriteFileError(e)),
            },
        }
    }

    /// Use `chown` to delegate parts of cgroup nodes to users other than root.
    pub fn delegate(&self, uid: Uid, modes: &[DelegateMode]) -> Result<(), CgroupError> {
        for mode in modes {
            let file = match mode {
                DelegateMode::DelegateNewSubtree => ".",
                DelegateMode::DelegateProcs => "cgroup.procs",
                DelegateMode::DelegateSubtreeControl => "cgroup.subtree_control",
                DelegateMode::DelegateThreads => "cgroup.threads",
            };
            let path = self.path.join(file);

            let res = chown(&path, Some(uid), None);
            match res {
                Ok(_) => {}
                Err(e) => {
                    let e = nix_to_io_error(e);
                    match e.kind() {
                        std::io::ErrorKind::PermissionDenied => {
                            if let Some(request_func) = self.request_func {
                                request_func(
                                    &PrivilegeOpType::DelegateNode,
                                    format!("chown {} {}", uid, escape(path.to_string_lossy()))
                                        .as_str(),
                                )
                                .map_err(CgroupError::RequestUserError)?
                            } else {
                                return Err(CgroupError::DelegateError(e));
                            }
                        }
                        _ => return Err(CgroupError::DelegateError(e)),
                    }
                }
            }
        }
        Ok(())
    }

    /// Parse `memory.peak` and get peak memory usage in current cgroup node.
    pub fn get_memory_peak(&self) -> Result<u64, CgroupError> {
        let contents = std::fs::read_to_string(self.path.join("memory.peak"))
            .map_err(CgroupError::ReadFileError)?;
        contents.trim_end().parse().map_err(|e| {
            CgroupError::ReadFileError(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
    }

    /// Parse `io.stat` and get I/O statistics in current cgroup node.
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

    macro_rules! nonroot_only {
        () => {
            if is_root() {
                warn!("Running as root, skipping");
                return;
            }
        };
    }

    #[test]
    fn get_current_node_pid() {
        let ctl = CgroupController::<_>::default();
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

    fn random_name(s: &str) -> String {
        format!("{}_{}", s, rand::random::<u64>())
    }

    fn create_test_node_on_root_node<F>(ctl: &CgroupController<F>) -> CgroupNode<F> where F: Func {
        // randomly generate a test node
        let test_node_name = random_name("test_node");
        let root = ctl.get_root_node().unwrap();
        let test_node = ctl
            .create_from_node_path(&root, &PathBuf::from(test_node_name), true)
            .unwrap();
        test_node
    }

    fn cleanup_node<F>(ctl: &CgroupController<F>, node: CgroupNode<F>) where F: Func {
        let root = ctl.get_root_node().unwrap();
        node.cleanup(&root).unwrap();
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
        let test_node = create_test_node_on_root_node(&ctl);

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
        let test_node = create_test_node_on_root_node(&ctl);

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
        let test_node = create_test_node_on_root_node(&ctl);

        test_node.move_process(pid).unwrap();
        let pid_list = test_node.get_pid_list().unwrap();
        assert!(pid_list.contains(&pid));

        // test if cleanup succeeds
        cleanup_node(&ctl, test_node);

        // kill the testing process
        handle.kill().unwrap();
    }

    #[test]
    fn utils_u32_to_bytes_test() {
        use utils::u32_to_bytes;
        let mut buf = [0u8; 10];
        assert_eq!(u32_to_bytes(0, &mut buf), 1);
        assert_eq!(buf[0], b'0');
        assert_eq!(u32_to_bytes(1, &mut buf), 1);
        assert_eq!(buf[0], b'1');
        assert_eq!(u32_to_bytes(123, &mut buf), 3);
        assert_eq!(buf[0], b'1');
        assert_eq!(buf[1], b'2');
        assert_eq!(buf[2], b'3');
        assert_eq!(u32_to_bytes(1234567890, &mut buf), 10);
        assert_eq!(buf[0], b'1');
        assert_eq!(buf[1], b'2');
        assert_eq!(buf[2], b'3');
        assert_eq!(buf[3], b'4');
        assert_eq!(buf[4], b'5');
        assert_eq!(buf[5], b'6');
        assert_eq!(buf[6], b'7');
        assert_eq!(buf[7], b'8');
        assert_eq!(buf[8], b'9');
        assert_eq!(buf[9], b'0');
    }

    #[test]
    fn request_func_test_create() {
        nonroot_only!();

        let node_name = random_name("test_node");

        let node_name_clone = node_name.clone();
        let ctl = CgroupController::new(
            CGROUPV2_DEFAULT_PATH,
            Some(Box::new(move |typ, cmd| {
                assert_eq!(typ, &PrivilegeOpType::CreateNode);
                assert_eq!(cmd, format!("mkdir -p /sys/fs/cgroup/{}", node_name_clone));
                Ok(())
            })),
        );
        let root = ctl.get_root_node().unwrap();

        let _test_node = ctl.create_from_node_path(&root, &PathBuf::from(node_name), true);
    }

    #[test]
    fn request_func_test_create_escape() {
        nonroot_only!();

        let node_name = "a\\b'\"   !_12345";

        let ctl = CgroupController::new(
            CGROUPV2_DEFAULT_PATH,
            Some(Box::new(move |typ, cmd| {
                assert_eq!(typ, &PrivilegeOpType::CreateNode);
                assert_eq!(cmd, "mkdir -p '/sys/fs/cgroup/a\\b'\\''\"   '\\!'_12345'");
                Ok(())
            })),
        );
        let root = ctl.get_root_node().unwrap();

        let _test_node = ctl.create_from_node_path(&root, &PathBuf::from(node_name), true);
    }

    fn request_func_example(pri: &PrivilegeOpType, cmd: &str) -> Result<(), std::io::Error> {
        println!("{:?}: {}", pri, cmd);
        Ok(())
    }

    #[test]
    fn request_func_test_create_example() {
        nonroot_only!();

        let node_name = random_name("test_node");

        let ctl =
            CgroupController::new(CGROUPV2_DEFAULT_PATH, Some(Box::new(request_func_example)));
        let root = ctl.get_root_node().unwrap();

        let _test_node = ctl.create_from_node_path(&root, &PathBuf::from(node_name), true);
    }

    #[test]
    fn request_func_test_move() {
        nonroot_only!();
        let ctl = CgroupController::new(
            CGROUPV2_DEFAULT_PATH,
            Some(Box::new(move |typ, cmd| {
                assert_eq!(typ, &PrivilegeOpType::MoveProcess);
                assert_eq!(
                    cmd,
                    format!("echo {} > /sys/fs/cgroup/cgroup.procs", std::process::id(),)
                );
                Ok(())
            })),
        );
        let root = ctl.get_root_node().unwrap();
        let _ = root.move_process(Pid::from_raw(std::process::id() as i32));
    }

    #[cfg(feature = "systemd")]
    #[test]
    fn systemd_scope_test() {
        nonroot_only!();

        let ctl = CgroupController::default();
        ctl.create_systemd_cgroup("cgumi-unittest").unwrap();
    }
}
