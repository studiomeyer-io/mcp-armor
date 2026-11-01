//! Primary-source advisories and independent internal scanner simulations.

pub mod feed;

pub use feed::{simulations, Cve, CveFeed, Severity, Simulation, SimulationFeed, FEED};
