# GANDIV — Real-World Usage Scenarios

## 1. Bug bounty recon on a new scope

```bash
python main.py scan --target target-company.com --full --threads 20 --report json,html
```

Open the HTML report, filter by risk = high/critical, and triage exposed
paths, missing security headers, and any zone-transfer or bucket findings
first — these are typically the fastest wins.

## 2. Pre-engagement OSINT for a pentest

```bash
python main.py scan --target "Acme Corp" --type org --full --report markdown
```

The Markdown report is easy to paste directly into a scoping document or
share with a client for validation before testing begins.

## 3. Checking your own digital footprint

```bash
python main.py scan --target you@example.com --type email
python main.py scan --target your_handle --type username
```

Review the `breach_exposure` and `username_match` findings, then follow up
manually on anything you didn't expect to be public.

## 4. Subdomain discovery before a DAST scan

```bash
python main.py scan --target example.com --report json
```

Feed the `subdomain` findings from the JSON report into a scanner like
SUDARSHAN or your DAST tool of choice as the target list.

## 5. Investigating a suspicious IP

```bash
python main.py scan --target 203.0.113.42 --type ip --full
```

With `SHODAN_API_KEY` set, this surfaces open ports, fingerprinted
services, and any known CVEs associated with the host.

## 6. Long-running scan with resume support

```bash
python main.py scan --target big-target.com --full --threads 5
# ...connection drops or you Ctrl+C...
python main.py resume --checkpoint ~/.gandiv/checkpoints/gandiv_big-target_com_checkpoint.json
```

## 7. Quick vs. full mode

- `--full` runs every applicable module, including `osint_aggregator`
  (dork generation, cross-referencing, paste-site search) — slower but
  most complete.
- Omitting `--full` skips aggregation and runs only the fast, high-signal
  modules — good for a first pass across many targets.

## 8. Cross-referencing findings

Run with `--full` and check the JSON report for `type: corroborated_finding`
entries — these are values independently confirmed by 2+ different sources
and are the highest-confidence leads in the whole report.

## 9. Integrating into a CI/attack-surface-monitoring pipeline

```bash
python main.py scan --target example.com --report json --output-dir ./ci-artifacts --quiet
```

Parse the resulting JSON (`stats.by_risk`) to fail a build or open a ticket
when new `critical`/`high` findings appear versus the previous run.

## 10. Building a client-facing summary

```bash
python main.py scan --target example.com --full --report html
```

The HTML report's search box and risk filters make it usable directly in a
client walkthrough call without any extra formatting work.
