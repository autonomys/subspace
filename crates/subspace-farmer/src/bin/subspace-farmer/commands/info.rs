use crate::commands::shared::print_disk_farm_info;
use std::path::PathBuf;

pub(crate) fn info(disk_farms: Vec<PathBuf>) {
    for (farm_index, disk_farm) in disk_farms.into_iter().enumerate() {
        if farm_index > 0 {
            println!();
        }

        print_disk_farm_info(disk_farm, farm_index);
    }
}
