# lattivant-lab

The integrated security lab for [Lattivant](https://github.com/karkat983) — an isolated,
fully reproducible environment that links **every engine** into one scripted scenario with known
ground truth. It is the capstone that proves the pieces compose: the AuthZ Fuzzer's verdict,
AgentTrace's instrumentation and side-effect correlation, EastWest's network context, the
Evidence Graph, and the Investigator, all threaded through a single story end to end.

Everything is local and synthetic — two tenants, authorized test identities, a tiny orders API
with a *seeded* authorization-check mutant, a mock email sink, and synthetic flows. No target is
ever external.

## The scenario, in seven steps

1. the **fuzzer** has verified (or not) a cross-tenant `PATCH` weakness;
2. a controlled **untrusted document** influences the agent (a taint signal);
3. the instrumented **agent** invokes the orders API;
4. the **gateway** records what actually happened — status *and* whether state changed;
5. synthetic **network** flows provide context (EastWest baselines);
6. the **evidence graph** correlates it into an incident candidate;
7. the **investigator** produces a cited, grounded timeline and opens a case.

The lab derives the security outcome **purely from the engines' output** and checks it against
the label it knew in advance.

## Ground truth: attempted vs achieved vs benign

Three variants make the central distinction concrete:

| Variant | Setup | Known outcome | Engines derive |
|---------|-------|---------------|----------------|
| `achieved_cross_tenant_write` | mutant removes the PATCH check; state actually changes | **AchievedUnauthorized** | verified side effect, R4 fires, network anomaly, incident **Confirmed** |
| `attempted_but_blocked` | hardened API refuses the same PATCH | **AttemptedOnly** | cross-tenant attempt, no verified effect, incident **Investigating** |
| `benign_admin_action` | an authorized admin performs the PATCH | **Benign** | no violation, incident **Dismissed** |

A 2xx status alone never promotes *attempted* to *achieved*: only an observed state change does.
In the achieved run the investigator even proposes an over-reaching "data was exfiltrated" causal
claim — and the post-checker **drops it**, because correlation is not causation.

## Try it

```sh
cargo run -p lattivant-lab
```

prints the ground-truth matrix (all three variants matching), confirms a clean reset reproduces
them byte-for-byte, and renders the achieved-variant investigation report.

```sh
cargo test              # all scenarios + the reproducibility check
cargo clippy --all-targets
```

The lab depends on every engine as a git dependency, so a build fetches
[`lattivant-platform`](https://github.com/karkat983/lattivant-platform),
[`agenttrace`](https://github.com/karkat983/agenttrace),
[`evidence-graph`](https://github.com/karkat983/evidence-graph),
[`eastwest`](https://github.com/karkat983/eastwest) and
[`investigator`](https://github.com/karkat983/investigator). Requires a recent stable Rust
toolchain (edition 2021, rustc ≥ 1.80).

## License

MIT. See [LICENSE](LICENSE).
