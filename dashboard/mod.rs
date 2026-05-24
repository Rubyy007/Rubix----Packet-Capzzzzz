// src/dashboard/mod.rs
//! HTTP dashboard — live web UI and REST API for RUBIX.
//!
//! Runs entirely in the slow path.  Zero fast-path impact:
//!   • Reads LiveStats via Arc<RwLock<LiveStats>> shared read lock only.
//!   • Commands route through the existing CommandHandler (already Arc-shared).
//!   • Runs in its own tokio::spawn task.
//!   • No code added to the packet loop.

#[path = "server.rs"]
pub mod server;
pub use server::{DashboardServer, generate_dashboard_token};