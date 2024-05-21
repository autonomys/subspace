//! Cluster version of the farmer
//!
//! This module contains isolated set of modules that implement cluster-specific functionality for
//! the farmer, allowing to distribute cooperating components across machines, while still working
//! together.
//!
//! Specifically, 4 separate components are extracted:
//! * controller
//! * farmer
//! * plotter
//! * cache
//!
//! ### Controller
//!
//! Controller connects to the node via RPC and DSN. It handles notifications from node and
//! orchestrates other components. It will send slot notifications to farmers, store and retrieve
//! pieces from caches on requests from DSN, etc.
//!
//! While there could be multiple controllers shared between farmers, each controller must have its
//! dedicated pool of caches and each cache should belong to a single controller. This allows to
//! shut down some controllers for upgrades and other maintenance tasks without affecting farmer's
//! ability to farm and receive rewards.
//!
//! ### Farmer
//!
//! Farmer maintains farms with plotted pieces and corresponding metadata. Farmer does audits and
//! proving, retrieves pieces from plotted sectors on request, but doesn’t do any caching or P2P
//! networking with DSN. When sectors need to be plotted/replotted, request will be sent to Plotter
//! to do that instead of doing it locally, though plotter and farmer can be co-located.
//!
//! Farmers receive (de-duplicated) slot notifications from all controllers and will send solution
//! back to the controller from which they received slot notification.
//!
//! ### Plotter
//!
//! Plotter needs to be able to do heavy compute with proportional amount of RAM for plotting
//! purposes.
//!
//! There could be any number of plotters in a cluster, adding more will increase total cluster
//! ability to plot concurrent sectors.
//!
//! ### Cache
//!
//! Cache helps with plotting process and with serving data to DSN. At the same time, writes and
//! reads are while random, they are done in large size and low frequency comparing in contrast to
//! farmer. Fast retrieval is important for plotters to not stay idle, but generally cache can work
//! even on HDDs.
//!
//! There could be any number of caches in the cluster, but each cache instance belongs to one of
//! the controllers. So if multiple controllers are present in the cluster, you'll want at least one
//! cache connected to each as well for optimal performance.

pub mod cache;
pub mod controller;
pub mod farmer;
pub mod nats_client;
pub mod plotter;
