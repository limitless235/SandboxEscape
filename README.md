# Defensive Agent Sandbox Isolation Lab

Local lab for **AI-agent sandbox containment**. The model is not the security boundary — tool policy, container hardening, and network segmentation are.

It shows both PASS and FAIL through configuration, with synthetic data only. It does **not** reproduce a real incident or ship an escape exploit.

> Even if the model behaves badly, the dummy production database stays unreachable.

## Run it

No Docker:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
make test-unit
make demo
cat audit/compare.md audit/lab-report.md audit/benign/trace.md
```

With Docker:

```bash
make locked-up
make test-isolation
make scorecard          # locked: all PASS
make demo-full          # locked PASS, leaky FAIL, restore locked
make leaky-up && make test-isolation    # expected FAIL
make locked-up
```

`make demo` copies the workspace into `audit/demo-workspace` (does not dirty tracked files). Scripted denials fail the walkthrough. `make agent-benign` runs against `sandbox/workspace`.

## How to read a run

**ALLOW** = a workspace tool ran (`/workspace`, local SQLite, inlined Python). Not dummy Postgres.

**DENY** = containment worked.

`make scorecard` / `make demo-full` ask whether the sandbox *could* reach `prod-db`. A failed probe is inconclusive, not a PASS. The agent never gets a production tool or an escape goal.

## What is locked

```text
sandbox → prod-db / internet / DNS / docker.sock / host FS   BLOCKED
sandbox → /workspace and local SQLite                        ALLOWED
```

Tools: `read_file`, `write_file`, `list_workspace`, `run_local_python`, `query_local_sqlite`.

Benign task: notes, numbers, SQLite, synthetic `records.txt`. Adversarial track: fixed disallowed requests, all DENY.

Break one control with `compose.leaky.yaml` / `compose.faults/*`, or several with `compose.chained.yaml`. Detectors should FAIL. That is a chained *misconfiguration*, not a chained exploit.

## Out of scope

No replay of OpenAI/Hugging Face or Kimi incidents. No package-proxy, SSRF, RCE, or exploit recipes. No helper whose job is an escape hatch. No real credentials or production data.

Deeper architecture and incident-*class* mapping: [docs/LAB_EXPLAINED.md](docs/LAB_EXPLAINED.md).
