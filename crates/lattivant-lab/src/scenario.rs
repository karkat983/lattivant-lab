//! The integrated seven-step scenario.
//!
//! One run threads a single story through every engine, for a chosen [`Variant`]:
//!
//! 1. the **fuzzer** has verified (or not) a cross-tenant PATCH weakness;
//! 2. a controlled **untrusted document** influences the agent (a taint signal);
//! 3. the instrumented **agent** invokes the orders API;
//! 4. the **gateway** records what actually happened (status + state change);
//! 5. synthetic **network** flows provide context (EastWest);
//! 6. the **evidence graph** correlates it into an incident candidate;
//! 7. the **investigator** produces a cited, grounded timeline and opens a case.
//!
//! The lab then derives the security outcome purely from the engines' output and checks it
//! against the known ground truth — and, crucially, keeps *attempted* and *achieved* distinct.

use chrono::{DateTime, TimeZone, Utc};

use agenttrace_core::{Achieved, AgentIdentity, ResourceRef, SpanId, ToolCall, ToolOutcome, TraceId};
use agenttrace_correlate::{Confidence, Correlator as AtCorrelator, GatewayEvent, Method};
use agenttrace_detect::{DetectionContext, Detector, TaintedCallSignal};
use eastwest_baseline::{AssetInventory, Baseline, BaselineConfig};
use eastwest_ingest::FlowAggregate;
use eastwest_flow::Protocol;
use evidence_graph_core::{AssertionKind, Edge, EdgeType, Node, NodeType, TemporalGraph};
use evidence_graph_correlate::Correlator as EgCorrelator;
use investigator_ground::{Claim, Evidence, FindingRecord, PostChecker, Response};
use investigator_incident::{Incident, IncidentState};
use lattivant_event::{ActorKind, Assertion, Event};

use crate::fixtures::{AuthzMutant, OrdersApi, TENANT_ALPHA, TENANT_BRAVO};
use crate::groundtruth::{Outcome, Variant};

const TRACE_HEX: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const SPAN_HEX: &str = "00f067aa0ba902b7";
const GATEWAY_EVENT_ID: &str = "gw-patch-evt";
const FINDING_ID: &str = "fuzzer-finding-patch";

fn at(min: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, 12, min, 0).unwrap()
}

/// The full result of one scenario run.
pub struct LabReport {
    /// The variant run.
    pub variant: Variant,
    /// The known ground-truth outcome.
    pub expected: Outcome,
    /// The outcome the engines derived.
    pub derived: Outcome,
    /// Whether the fuzzer verified a weakness.
    pub fuzzer_verified_weakness: bool,
    /// The correlation confidence label for the agent's side effect.
    pub side_effect_confidence: String,
    /// Whether detection rule R4 (untrusted→privileged) fired.
    pub r4_fired: bool,
    /// Whether EastWest raised a network anomaly as context.
    pub network_anomaly: bool,
    /// The incident's final state.
    pub incident_state: IncidentState,
    /// The number of grounded claims the investigator produced.
    pub grounded_claims: usize,
    /// Whether the investigator refused (insufficient evidence).
    pub investigator_refused: bool,
    /// The rendered investigation report.
    pub report_markdown: String,
}

impl LabReport {
    /// Whether the engines' derived outcome matches ground truth.
    pub fn matches_ground_truth(&self) -> bool {
        self.derived == self.expected
    }
}

/// Run one scenario variant end-to-end across the engines.
pub fn run(variant: Variant) -> LabReport {
    let (mutant, is_admin) = match variant {
        Variant::AchievedCrossTenantWrite => (AuthzMutant::CrossTenantPatchAllowed, false),
        Variant::AttemptedButBlocked => (AuthzMutant::None, false),
        Variant::BenignAdminAction => (AuthzMutant::None, true),
    };

    // ---- Step 1: the fuzzer's verdict on the PATCH weakness ----
    // The fuzzer verifies the weakness only when the mutant actually removes the check.
    let fuzzer_verified_weakness = mutant == AuthzMutant::CrossTenantPatchAllowed;

    // ---- Steps 3 + 4: the agent calls the API; the gateway records the real outcome ----
    let api = OrdersApi::seeded(mutant);
    let (status, state_changed) = api.patch(TENANT_ALPHA, is_admin, "order-bravo-1");

    let trace_id = TraceId::parse(TRACE_HEX).unwrap();
    let span_id = SpanId::parse(SPAN_HEX).unwrap();
    let call = ToolCall {
        trace_id: trace_id.clone(),
        span_id: span_id.clone(),
        parent_span_id: None,
        identity: AgentIdentity::new(TENANT_ALPHA, "assistant-7", "sess-lab"),
        tool_name: "patch_order".into(),
        operation: "PATCH /orders/{id}".into(),
        target: ResourceRef::new("order", "order-bravo-1").owned_by(TENANT_BRAVO),
        arguments: indexmap::IndexMap::new(),
        outcome: ToolOutcome::completed(
            if state_changed { Achieved::Wrote } else { Achieved::None },
            Some(status as i64),
        ),
        started_at: at(0),
        ended_at: at(1),
    };
    let gateway = GatewayEvent {
        event_id: GATEWAY_EVENT_ID.into(),
        trace_id,
        parent_span_id: Some(span_id),
        actor_tenant: TENANT_ALPHA.into(),
        principal_id: "assistant-7".into(),
        is_admin,
        method: Method::Patch,
        operation: "PATCH /orders/{id}".into(),
        resource_class: Some("order".into()),
        resource_id: Some("order-bravo-1".into()),
        owner_tenant: Some(TENANT_BRAVO.into()),
        status,
        response_bytes: 0,
        state_changed: Some(state_changed),
        observed_at: at(1),
    };

    let correlation = AtCorrelator::default().correlate(&[call], &[gateway]);
    let side_effect = correlation.side_effects.first().cloned();
    let (side_effect_confidence, se_unauthorized, se_owner_mismatch) = match &side_effect {
        Some(se) => (format!("{:?}", se.confidence), se.unauthorized_effect && se.confidence == Confidence::Verified, se.owner_mismatch),
        None => ("none".to_string(), false, false),
    };

    // ---- Step 2: the untrusted document's influence (a taint signal for R4) ----
    let injected = !is_admin; // the benign admin was not prompted by an injected document
    let mut ctx = DetectionContext::for_tenant(TENANT_ALPHA);
    if let Some(se) = side_effect.clone() {
        ctx = ctx.with_side_effect(se);
    }
    if injected {
        ctx = ctx.with_tainted_call(TaintedCallSignal {
            session_id: "sess-lab".into(),
            span_id: SPAN_HEX.into(),
            operation: "PATCH /orders/{id}".into(),
            tainted_args: vec!["order_id".into()],
            from_untrusted: true,
            event_id: GATEWAY_EVENT_ID.into(),
            at: at(0),
        });
    }
    let detection = Detector::default().run_at(&ctx, at(5));
    let r4_fired = detection.alerts.iter().any(|d| d.rule_id == "R4");

    // ---- Step 5: synthetic network context (EastWest) ----
    let network_anomaly = network_context(variant);

    // ---- Step 6: correlate into an incident candidate on the evidence graph ----
    let graph = build_graph(fuzzer_verified_weakness);
    let seed = if fuzzer_verified_weakness { "finding" } else { "agent" };
    let candidate = EgCorrelator::default().candidate_from_seed(&graph, seed, at(5));

    // ---- Derive the outcome purely from engine output ----
    let derived = if se_unauthorized {
        Outcome::AchievedUnauthorized
    } else if se_owner_mismatch {
        Outcome::AttemptedOnly
    } else {
        Outcome::Benign
    };

    // ---- Step 7: the investigator builds a grounded, cited timeline and opens a case ----
    let (response, incident) = investigate(variant, derived, &candidate_evidence(&candidate));

    let grounded_claims = match &response {
        Response::Answer { claims } => claims.len(),
        Response::Refusal { .. } => 0,
    };
    let investigator_refused = response.is_refusal();

    let report_markdown = render_report(&incident, &response);

    LabReport {
        variant,
        expected: variant.expected_outcome(),
        derived,
        fuzzer_verified_weakness,
        side_effect_confidence,
        r4_fired,
        network_anomaly,
        incident_state: incident.state,
        grounded_claims,
        investigator_refused,
        report_markdown,
    }
}

/// Build synthetic network context: an exfil-like egress anomaly only when an effect was
/// achieved, otherwise normal traffic.
fn network_context(variant: Variant) -> bool {
    let mut inv = AssetInventory::new();
    inv.set_role("agent-workload", "app");
    inv.set_role("db-1", "db");
    inv.set_role("email-sink", "external");
    inv.mark_vulnerable("email-sink");

    let win = |d: i64| Utc.timestamp_opt(1_767_225_600 + d * 86_400, 0).unwrap();
    let agg = |src: &str, dst: &str, port: u16, d: i64| FlowAggregate {
        tenant_id: TENANT_ALPHA.into(),
        src: src.into(),
        dst: dst.into(),
        dst_port: port,
        protocol: Protocol::Tcp,
        window_start: win(d),
        window_end: win(d) + chrono::Duration::seconds(86_400),
        flow_count: 10,
        bytes: 1000,
        packets: 20,
        has_unknown_counts: false,
        flow_ids: vec![format!("flow-{src}-{dst}-{d}")],
    };

    // 14 days of normal agent -> db traffic.
    let history: Vec<FlowAggregate> = (0..14).map(|d| agg("agent-workload", "db-1", 5432, d)).collect();
    let baseline = Baseline::build(&history, &inv, BaselineConfig::default());

    // Only the achieved-write variant produces the exfil egress to the external sink.
    let current = match variant {
        Variant::AchievedCrossTenantWrite => vec![agg("agent-workload", "email-sink", 443, 14)],
        _ => vec![agg("agent-workload", "db-1", 5432, 14)],
    };
    !baseline.assess(&current, &inv).is_empty()
}

/// Build the evidence graph for the scenario.
fn build_graph(with_finding: bool) -> TemporalGraph {
    let mut g = TemporalGraph::new();
    for (id, ty) in [
        ("agent", NodeType::Agent),
        ("resource", NodeType::Resource),
        ("flow", NodeType::Workload),
    ] {
        g.add_node(Node::new(id, TENANT_ALPHA, ty));
    }
    // observed: the agent accessed the resource (backed by the gateway event)
    g.add_edge(Edge {
        id: "ed-agent-res".into(),
        tenant_id: TENANT_ALPHA.into(),
        edge_type: EdgeType::Accesses,
        src: "agent".into(),
        dst: "resource".into(),
        valid_from: at(0),
        valid_to: None,
        provenance_event_ids: vec![GATEWAY_EVENT_ID.into()],
        assertion_kind: AssertionKind::Observed,
        confidence: 0.95,
        rule_id: None,
    })
    .unwrap();
    // inferred, association-only: the resource correlates with a network flow
    g.add_edge(Edge {
        id: "ed-res-flow".into(),
        tenant_id: TENANT_ALPHA.into(),
        edge_type: EdgeType::CorrelatedWith,
        src: "resource".into(),
        dst: "flow".into(),
        valid_from: at(0),
        valid_to: None,
        provenance_event_ids: vec!["eastwest-flow".into()],
        assertion_kind: AssertionKind::InferredStat,
        confidence: 0.5,
        rule_id: Some("flow-correlation-v1".into()),
    })
    .unwrap();
    if with_finding {
        g.add_node(Node::new("finding", TENANT_ALPHA, NodeType::Finding));
        g.add_edge(Edge {
            id: "ed-finding-agent".into(),
            tenant_id: TENANT_ALPHA.into(),
            edge_type: EdgeType::Affects,
            src: "finding".into(),
            dst: "agent".into(),
            valid_from: at(0),
            valid_to: None,
            provenance_event_ids: vec![FINDING_ID.into()],
            assertion_kind: AssertionKind::Observed,
            confidence: 1.0,
            rule_id: None,
        })
        .unwrap();
    }
    g
}

/// The evidence ids gathered by the graph correlation (for the investigator).
fn candidate_evidence(candidate: &Option<evidence_graph_correlate::IncidentCandidate>) -> Vec<String> {
    candidate
        .as_ref()
        .map(|c| c.supporting_event_ids.clone())
        .unwrap_or_default()
}

/// Build the gateway event as a platform event the investigator can cite.
fn gateway_platform_event() -> Event {
    Event::builder("net.http", TENANT_ALPHA)
        .event_id(GATEWAY_EVENT_ID)
        .source_engine("authz")
        .actor(ActorKind::Service, "api-gateway")
        .action("operation", "PATCH /orders/{id}")
        .target("owner_tenant", TENANT_BRAVO)
        .outcome("observed", None)
        .assertion(Assertion::Observed)
        .build()
        .unwrap()
}

fn finding_record() -> FindingRecord {
    FindingRecord {
        id: FINDING_ID.into(),
        tenant_id: TENANT_ALPHA.into(),
        title: "Verified cross-tenant PATCH".into(),
        verified: true,
        supporting_event_ids: vec![GATEWAY_EVENT_ID.into()],
    }
}

/// Run the investigator: assemble evidence, propose claims, post-check, and open a case.
fn investigate(
    variant: Variant,
    derived: Outcome,
    _graph_evidence: &[String],
) -> (Response, Incident) {
    // evidence the investigator may cite: the gateway event always; the finding only when the
    // fuzzer verified a weakness.
    let mut retrieved: Vec<Evidence> = vec![Evidence::Event(Box::new(gateway_platform_event()))];
    if matches!(variant, Variant::AchievedCrossTenantWrite) {
        retrieved.push(Evidence::Finding(finding_record()));
    }

    let claims = match derived {
        Outcome::AchievedUnauthorized => vec![
            Claim::fact(
                "A verified cross-tenant PATCH weakness exists.",
                vec![FINDING_ID.into()],
            ),
            Claim::fact(
                "Agent assistant-7 issued a cross-tenant PATCH to order-bravo-1.",
                vec![GATEWAY_EVENT_ID.into()],
            ),
            // deliberate over-reach: a causal exfil claim with no causal evidence -> rejected
            Claim::causal("The change was exfiltrated to an external sink.", vec![]),
        ],
        Outcome::AttemptedOnly => vec![Claim::fact(
            "A cross-tenant PATCH was attempted and denied.",
            vec![GATEWAY_EVENT_ID.into()],
        )],
        Outcome::Benign => vec![Claim::fact(
            "An authorized administrator performed the PATCH.",
            vec![GATEWAY_EVENT_ID.into()],
        )],
    };
    let response = PostChecker::new(TENANT_ALPHA, &retrieved).respond(claims);

    // open and advance an incident according to the outcome
    let mut incident = Incident::open(
        format!("inc-{}", variant.label()),
        TENANT_ALPHA,
        "Agent cross-tenant PATCH",
        "analyst-1",
        at(10),
    );
    incident.attach_evidence(GATEWAY_EVENT_ID, "analyst-1", at(10));
    incident
        .transition(IncidentState::Investigating, "analyst-1", "triage", at(11))
        .unwrap();
    match derived {
        Outcome::AchievedUnauthorized => {
            incident.attach_evidence(FINDING_ID, "analyst-1", at(11));
            incident
                .transition(IncidentState::Confirmed, "analyst-1", "reproduced", at(12))
                .unwrap();
        }
        Outcome::AttemptedOnly => {
            incident.record_decision("monitor; attempt was blocked", "analyst-1", at(12));
        }
        Outcome::Benign => {
            incident
                .mark_false_positive("analyst-1", "authorized admin action", at(12))
                .unwrap();
        }
    }
    (response, incident)
}

fn render_report(incident: &Incident, response: &Response) -> String {
    use investigator_report::{ConfidenceMethod, EdgeView, EvidenceView, InvestigationReport, RedactionStatus};
    let edges = vec![
        EdgeView {
            src: "agent".into(),
            dst: "resource".into(),
            relation: "accesses".into(),
            confidence_method: ConfidenceMethod::Observed,
            causal: true,
            evidence_ids: vec![GATEWAY_EVENT_ID.into()],
            timestamp: at(0),
        },
        EdgeView {
            src: "resource".into(),
            dst: "flow".into(),
            relation: "correlated_with".into(),
            confidence_method: ConfidenceMethod::InferredStat,
            causal: false,
            evidence_ids: vec!["eastwest-flow".into()],
            timestamp: at(0),
        },
    ];
    let evidence = vec![EvidenceView {
        id: GATEWAY_EVENT_ID.into(),
        kind: "event".into(),
        timestamp: at(0),
        redaction: RedactionStatus::Partial,
        missing_telemetry: vec![],
    }];
    InvestigationReport::new(incident, response, &evidence, &edges).to_markdown()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn achieved_variant_is_verified_and_confirmed() {
        let r = run(Variant::AchievedCrossTenantWrite);
        assert_eq!(r.derived, Outcome::AchievedUnauthorized);
        assert!(r.matches_ground_truth());
        assert!(r.fuzzer_verified_weakness);
        assert_eq!(r.side_effect_confidence, "Verified");
        assert!(r.r4_fired);
        assert!(r.network_anomaly);
        assert_eq!(r.incident_state, IncidentState::Confirmed);
        // the over-reaching exfil causal claim was dropped; 2 grounded facts remain
        assert_eq!(r.grounded_claims, 2);
        assert!(!r.investigator_refused);
    }

    #[test]
    fn attempted_variant_is_distinct_from_achieved() {
        let r = run(Variant::AttemptedButBlocked);
        assert_eq!(r.derived, Outcome::AttemptedOnly);
        assert!(r.matches_ground_truth());
        assert!(!r.fuzzer_verified_weakness);
        assert_ne!(r.side_effect_confidence, "Verified");
        assert!(!r.network_anomaly);
        assert_eq!(r.incident_state, IncidentState::Investigating);
    }

    #[test]
    fn benign_admin_variant_is_not_a_violation() {
        let r = run(Variant::BenignAdminAction);
        assert_eq!(r.derived, Outcome::Benign);
        assert!(r.matches_ground_truth());
        assert!(!r.r4_fired);
        assert_eq!(r.incident_state, IncidentState::Dismissed);
    }

    #[test]
    fn report_distinguishes_observed_from_inferred() {
        let r = run(Variant::AchievedCrossTenantWrite);
        assert!(r.report_markdown.contains("● agent"));
        assert!(r.report_markdown.contains("◇ resource"));
        assert!(!r.report_markdown.contains("exfiltrated")); // rejected claim never shown
    }
}
