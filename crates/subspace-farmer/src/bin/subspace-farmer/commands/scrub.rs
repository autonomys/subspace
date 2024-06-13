use rayon::prelude::*;
use std::path::PathBuf;
use subspace_farmer::single_disk_farm::{ScrubTarget, SingleDiskFarm};
use tracing::{error, info, info_span};

pub(crate) fn scrub(
    disk_farms: &[PathBuf],
    disable_farm_locking: bool,
    target: ScrubTarget,
    dry_run: bool,
) {
    disk_farms
        .into_par_iter()
        .enumerate()
        .for_each(|(farm_index, directory)| {
            let span = info_span!("", %farm_index);
            let _span_guard = span.enter();
            info!(
                path = %directory.display(),
                "Start scrubbing farm"
            );

            match SingleDiskFarm::scrub(directory, disable_farm_locking, target, dry_run) {
                Ok(()) => {
                    info!(
                        path = %directory.display(),
                        "Farm checked successfully"
                    );
                }
                Err(error) => {
                    error!(
                        path = %directory.display(),
                        %error,
                        "Irrecoverable farm error occurred, your file system might need to be \
                        repaired or disk might need to be replaced"
                    );
                }
            }
        });
}
