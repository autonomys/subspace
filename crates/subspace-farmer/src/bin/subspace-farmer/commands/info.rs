use crate::commands::shared::print_disk_farm_info;
use std::path::PathBuf;

pub(crate) fn info(disk_farms: Vec<PathBuf>) {
    for (disk_farm_index, disk_farm) in disk_farms.into_iter().enumerate() {
        if disk_farm_index > 0 {
            println!();
        }

        print_disk_farm_info(disk_farm, disk_farm_index);
    }
}
