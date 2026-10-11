//! Ground truth for the lab.
//!
//! The point of a controlled lab is that we *know* the right answer in advance, so the engines'
//! output can be scored against it. Each scenario variant has a known [`Outcome`], and the
//! lab's definition of done is that a clean reset reproduces these labels and keeps
//! *attempted* and *achieved* outcomes distinguishable.

use serde::{Deserialize, Serialize};

/// The known security outcome of a scenario variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Authorized activity; no violation.
    Benign,
    /// An attack was attempted but no unauthorized effect was achieved.
    AttemptedOnly,
    /// A reproducible, verified unauthorized effect occurred.
    AchievedUnauthorized,
}

/// A scenario the lab can run, each with its known ground-truth outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// The mutant API allows a cross-tenant PATCH that changes state — achieved.
    AchievedCrossTenantWrite,
    /// The hardened API refuses the same PATCH — the attack is only attempted.
    AttemptedButBlocked,
    /// An authorized admin performs the same operation — benign.
    BenignAdminAction,
}

impl Variant {
    /// The known outcome for this variant.
    pub fn expected_outcome(self) -> Outcome {
        match self {
            Variant::AchievedCrossTenantWrite => Outcome::AchievedUnauthorized,
            Variant::AttemptedButBlocked => Outcome::AttemptedOnly,
            Variant::BenignAdminAction => Outcome::Benign,
        }
    }

    /// A short label.
    pub fn label(self) -> &'static str {
        match self {
            Variant::AchievedCrossTenantWrite => "achieved_cross_tenant_write",
            Variant::AttemptedButBlocked => "attempted_but_blocked",
            Variant::BenignAdminAction => "benign_admin_action",
        }
    }

    /// Every variant, for a full lab run.
    pub fn all() -> [Variant; 3] {
        [
            Variant::AchievedCrossTenantWrite,
            Variant::AttemptedButBlocked,
            Variant::BenignAdminAction,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempted_and_achieved_are_distinct_labels() {
        assert_ne!(
            Variant::AchievedCrossTenantWrite.expected_outcome(),
            Variant::AttemptedButBlocked.expected_outcome()
        );
        assert_eq!(Variant::BenignAdminAction.expected_outcome(), Outcome::Benign);
    }
}
