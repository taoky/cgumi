use std::path::PathBuf;
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
            std::fs::read("/proc/self/cgroup").map_err(CgroupError::ReadFileError)?;

        let hierarchy_list = String::from_utf8(cgroup_file_contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            .map_err(CgroupError::ReadFileError)?;
        let hierarchy_list: Vec<_> = hierarchy_list.trim().splitn(3, ':').collect();

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

    pub fn get_pid_list(&self) -> Result<Vec<u64>, CgroupError> {
        // read cgroup.procs file
        let pid_list_contents =
            std::fs::read(self.path.join("cgroup.procs")).map_err(CgroupError::ReadFileError)?;
        let pid_list: Result<Vec<u64>, _> = String::from_utf8(pid_list_contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            .map_err(CgroupError::ReadFileError)?
            .trim_end()
            .split('\n')
            .map(|pid| pid.trim().parse())
            .collect();
        pid_list.map_err(|e| {
            CgroupError::ReadFileError(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    #[test]
    fn show_current_node_pid() {
        let ctl = CgroupController::default();
        let node = ctl.get_from_current().unwrap();
        let pid_list = node.get_pid_list().unwrap();
        assert!(pid_list.contains(&std::process::id().into()));
    }
}
