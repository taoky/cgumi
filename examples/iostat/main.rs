// Get the io stat of the root cgroup
// Print read, write, discard Byte/s and IOPs every second.

use std::{collections::HashMap, time::Duration};

use cgumi::IOStat;
use chrono::Local;

extern crate cgumi;

fn main() {
    let ctl = cgumi::CgroupController::default();
    let root = ctl.get_root_node().unwrap();

    let mut device_map: HashMap<String, IOStat> = HashMap::new();

    loop {
        let iostats = root.get_io_stat().unwrap();
        for iostat in iostats {
            if device_map.contains_key(&iostat.device) {
                let rbytesec = iostat.rbytes - device_map[&iostat.device].rbytes;
                let wbytesec = iostat.wbytes - device_map[&iostat.device].wbytes;
                let dbytesec = iostat.dbytes - device_map[&iostat.device].dbytes;

                let riops = iostat.rios - device_map[&iostat.device].rios;
                let wiops = iostat.wios - device_map[&iostat.device].wios;
                let diops = iostat.dios - device_map[&iostat.device].dios;

                if rbytesec > 0
                    || wbytesec > 0
                    || dbytesec > 0
                    || riops > 0
                    || wiops > 0
                    || diops > 0
                {
                    println!("[{:?}] {}: {}B/s read, {}B/s write, {}B/s discard, {} iops read, {} iops write, {} iops discard",
                        Local::now(), iostat.device, rbytesec, wbytesec, dbytesec, riops, wiops, diops);
                }
            }
            device_map.insert(iostat.device.clone(), iostat);
        }

        std::thread::sleep(Duration::from_secs(1))
    }
}
