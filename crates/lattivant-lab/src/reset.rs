//! Reset and reproducibility.
//!
//! The lab's definition of done is that a clean reset produces reproducible ground truth. Every
//! fixture here is pure and deterministic — fixed ids, fixed timestamps, no clocks or randomness
//! — so "reset" is simply running again from scratch. [`reproduces`] proves it: two independent
//! runs of every variant produce byte-identical reports and identical derived outcomes.

use crate::groundtruth::{Outcome, Variant};
use crate::scenario::{run, LabReport};

/// Run every scenario variant once.
pub fn run_all() -> Vec<LabReport> {
    Variant::all().into_iter().map(run).collect()
}

/// Whether the engines' derived outcomes match ground truth for every variant, *and* a second
/// run reproduces the same outcomes and reports exactly.
pub fn reproduces() -> bool {
    let first = run_all();
    // every variant matches its known ground truth
    if !first.iter().all(|r| r.matches_ground_truth()) {
        return false;
    }
    // attempted and achieved are actually distinguishable in the output
    let outcomes: Vec<Outcome> = first.iter().map(|r| r.derived).collect();
    if !outcomes.contains(&Outcome::AchievedUnauthorized)
        || !outcomes.contains(&Outcome::AttemptedOnly)
        || !outcomes.contains(&Outcome::Benign)
    {
        return false;
    }
    // a clean reset (second run) is identical
    let second = run_all();
    first.len() == second.len()
        && first.iter().zip(&second).all(|(a, b)| {
            a.derived == b.derived && a.report_markdown == b.report_markdown
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_reset_reproduces_ground_truth() {
        assert!(reproduces());
    }

    #[test]
    fn all_three_outcomes_are_represented() {
        let outcomes: Vec<Outcome> = run_all().into_iter().map(|r| r.derived).collect();
        assert!(outcomes.contains(&Outcome::AchievedUnauthorized));
        assert!(outcomes.contains(&Outcome::AttemptedOnly));
        assert!(outcomes.contains(&Outcome::Benign));
    }
}
