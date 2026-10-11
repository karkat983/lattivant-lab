//! The lab's isolated, reproducible fixtures.
//!
//! Everything here is local and synthetic: two tenants, authorized test identities, a tiny
//! multi-tenant orders API whose authorization check can be *mutated* (a seeded check-removal
//! bug), synthetic workloads, and a mock email sink that stands in for an external egress
//! destination. No fixture touches anything outside the process.

use std::cell::RefCell;

/// The two tenants in the lab.
pub const TENANT_ALPHA: &str = "alpha";
/// The second tenant, whose data must stay isolated from alpha.
pub const TENANT_BRAVO: &str = "bravo";

/// An authorized test identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestIdentity {
    /// The principal id.
    pub principal: String,
    /// The tenant it belongs to.
    pub tenant: String,
    /// Whether it is an administrator (authorized broad access).
    pub is_admin: bool,
}

impl TestIdentity {
    /// The seeded identities: an alpha agent, an alpha admin, and a bravo owner.
    pub fn seeded() -> Vec<TestIdentity> {
        vec![
            TestIdentity { principal: "assistant-7".into(), tenant: TENANT_ALPHA.into(), is_admin: false },
            TestIdentity { principal: "alpha-admin".into(), tenant: TENANT_ALPHA.into(), is_admin: true },
            TestIdentity { principal: "bravo-owner".into(), tenant: TENANT_BRAVO.into(), is_admin: false },
        ]
    }
}

/// Which authorization check (if any) has been removed — the seeded mutant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthzMutant {
    /// The API is hardened: ownership is enforced on every operation.
    None,
    /// The ownership check on PATCH is removed — a cross-tenant write weakness.
    CrossTenantPatchAllowed,
}

/// An order in the multi-tenant orders API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// The order id.
    pub id: String,
    /// The tenant that owns it.
    pub owner_tenant: String,
}

/// A minimal multi-tenant orders API whose PATCH check can be mutated.
pub struct OrdersApi {
    orders: Vec<Order>,
    mutant: AuthzMutant,
    /// Records whether the last mutating call actually changed state.
    last_write_changed: RefCell<bool>,
}

impl OrdersApi {
    /// Seed the API with one order per tenant and a chosen mutant.
    pub fn seeded(mutant: AuthzMutant) -> Self {
        OrdersApi {
            orders: vec![
                Order { id: "order-alpha-1".into(), owner_tenant: TENANT_ALPHA.into() },
                Order { id: "order-bravo-1".into(), owner_tenant: TENANT_BRAVO.into() },
            ],
            mutant,
            last_write_changed: RefCell::new(false),
        }
    }

    fn order(&self, id: &str) -> Option<&Order> {
        self.orders.iter().find(|o| o.id == id)
    }

    /// Whether a principal may PATCH an order, under the current mutant.
    pub fn may_patch(&self, actor_tenant: &str, is_admin: bool, order_id: &str) -> bool {
        let Some(order) = self.order(order_id) else {
            return false;
        };
        if is_admin || order.owner_tenant == actor_tenant {
            return true;
        }
        // The mutant: the ownership check on PATCH is removed, so a cross-tenant write slips.
        matches!(self.mutant, AuthzMutant::CrossTenantPatchAllowed)
    }

    /// Attempt a PATCH. Returns `(http_status, state_changed)` and records the change.
    pub fn patch(&self, actor_tenant: &str, is_admin: bool, order_id: &str) -> (u16, bool) {
        if self.may_patch(actor_tenant, is_admin, order_id) {
            *self.last_write_changed.borrow_mut() = true;
            (200, true)
        } else {
            *self.last_write_changed.borrow_mut() = false;
            (403, false)
        }
    }

    /// Whether the last mutating call changed state (the oracle the gateway reports).
    pub fn last_write_changed(&self) -> bool {
        *self.last_write_changed.borrow()
    }
}

/// A mock email sink standing in for an external egress destination.
#[derive(Default)]
pub struct MockEmailSink {
    sent: RefCell<Vec<String>>,
}

impl MockEmailSink {
    /// A new, empty sink.
    pub fn new() -> Self {
        MockEmailSink::default()
    }

    /// Record an outbound email body.
    pub fn send(&self, body: impl Into<String>) {
        self.sent.borrow_mut().push(body.into());
    }

    /// How many emails were sent.
    pub fn count(&self) -> usize {
        self.sent.borrow().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_api_blocks_cross_tenant_patch() {
        let api = OrdersApi::seeded(AuthzMutant::None);
        // alpha patching bravo's order is refused and changes nothing
        assert_eq!(api.patch(TENANT_ALPHA, false, "order-bravo-1"), (403, false));
        assert!(!api.last_write_changed());
    }

    #[test]
    fn mutant_api_allows_cross_tenant_patch() {
        let api = OrdersApi::seeded(AuthzMutant::CrossTenantPatchAllowed);
        assert_eq!(api.patch(TENANT_ALPHA, false, "order-bravo-1"), (200, true));
        assert!(api.last_write_changed());
    }

    #[test]
    fn admin_and_owner_may_always_patch() {
        let api = OrdersApi::seeded(AuthzMutant::None);
        assert!(api.may_patch(TENANT_ALPHA, true, "order-bravo-1")); // admin
        assert!(api.may_patch(TENANT_BRAVO, false, "order-bravo-1")); // owner
    }

    #[test]
    fn email_sink_counts_sends() {
        let sink = MockEmailSink::new();
        sink.send("exfiltrated order data");
        assert_eq!(sink.count(), 1);
    }

    #[test]
    fn seeded_identities_span_both_tenants() {
        let ids = TestIdentity::seeded();
        assert!(ids.iter().any(|i| i.tenant == TENANT_ALPHA && !i.is_admin));
        assert!(ids.iter().any(|i| i.tenant == TENANT_BRAVO));
    }
}
