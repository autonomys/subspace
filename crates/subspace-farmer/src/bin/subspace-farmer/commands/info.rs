use crate::commands::shared::print_disk_farm_info;
use crate::DiskFarm;

pub(crate) fn info(disk_farms: Vec<DiskFarm>) {
    for (disk_farm_index, disk_farm) in disk_farms.into_iter().enumerate() {
        if disk_farm_index > 0 {
            println!();
        }

        let DiskFarm { directory, .. } = disk_farm;

        print_disk_farm_info(directory, disk_farm_index);
    }
}
