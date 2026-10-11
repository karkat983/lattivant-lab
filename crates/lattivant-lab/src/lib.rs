//! The Lattivant integrated security lab.
//!
//! An isolated, fully reproducible environment that links every engine — the AuthZ Fuzzer's
//! verdict, AgentTrace's instrumentation and correlation, EastWest's network context, the
//! Evidence Graph, and the Investigator — into one scripted scenario with known ground truth.
//!
//! Each [`Variant`](groundtruth::Variant) threads a single story through all seven steps and the
//! lab derives the security outcome *purely from the engines' output*, then checks it against
//! the label it knew in advance. The three variants make the key distinction concrete:
//! **achieved** (a mutant lets a cross-tenant PATCH change state — verified), **attempted** (the
//! hardened API blocks the same PATCH — not verified), and **benign** (an authorized admin does
//! it). A clean [`reset`] reproduces all of this byte-for-byte.
//!
//! Everything is local and synthetic: see [`fixtures`]. No target is ever external.

pub mod fixtures;
pub mod groundtruth;
pub mod reset;
pub mod scenario;

pub use groundtruth::{Outcome, Variant};
pub use reset::{reproduces, run_all};
pub use scenario::{run, LabReport};
