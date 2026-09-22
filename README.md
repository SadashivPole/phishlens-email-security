# PhishLens

PhishLens is a local-first, explainable email-analysis tool for SOC triage. It turns an `.eml` message into a bounded score, a cautious verdict, explicit completeness states, IOC records, and provenance-backed evidence.

## What problem it solves

A SOC analyst often needs a fast first-pass answer without uploading a potentially sensitive message to an external service. PhishLens provides a reproducible local analysis of identity, authentication, URLs, content, mail flow, attachments, and optional threat-intelligence observations. It is designed to explain what was observed and what could not be evaluated; it is not an autonomous incident-response system.

## Architecture and data flow

```text
.eml bytes
  -> bounded stdlib MIME parser
  -> ParsedEmail and attachment metadata
  -> deterministic local analyzers
       identity/authentication, URLs, content, mail flow, attachments
  -> IOC extraction and normalization
  -> optional provider orchestration
       VirusTotal and AbuseIPDB, configured by environment only
  -> normalized ThreatIntelResult records
  -> bounded threat-intelligence policy evidence
  -> deterministic scoring and verdict policy
  -> AnalysisResult / safe JSON
```

All local detection and scoring is deterministic. Provider results are evidence records; they do not directly override the verdict. LLM output is not used anywhere in the pipeline.

Authentication alignment is similarly limited: PhishLens compares the visible From domain with SPF and DKIM domains asserted by received Authentication-Results. It reports strict equality and relaxed equality using the bundled Public Suffix List implementation, but it does not know the effective DMARC alignment mode and therefore reports effective alignment as unknown. These comparisons do not independently evaluate SPF DNS policy or verify DKIM signatures.

## Verdicts

- **CLEAN** — required local analysis completed without material suspicious evidence. This does not prove global safety.
- **SUSPICIOUS** — local evidence is materially concerning and requires analyst review, but no defined hard indicator established `MALICIOUS`.
- **MALICIOUS** — reserved for an explicitly defined high-confidence hard indicator. A provider response alone cannot force this verdict.
- **UNRESOLVED** — a required local analysis area could not be safely evaluated, such as malformed input, missing required authentication evidence, or materially incomplete URL parsing.

Provider timeout, rate-limit, error, unavailable, and partial states remain explicit TI evidence. They do not silently become `no_match`, and they do not replace a normal local verdict with `UNRESOLVED` when required local analysis is otherwise complete.

## Threat intelligence

Threat intelligence is optional and isolated from deterministic local scoring.

- **VirusTotal** supports IP, domain, URL, and SHA-256 IOC lookups.
- **AbuseIPDB** supports IP lookups only. Other IOC types return an explicit unsupported/unavailable result without a request.
- Results are normalized to `ThreatIntelResult` with provider, IOC type/value, status, disposition, confidence, provenance, and observed indicators.
- TI evidence is deduplicated by provider and IOC and bounded by the Phase 3B.4 policy.
- `match`, `no_match`, `partial`, `timeout`, `rate_limited`, `error`, `unavailable`, and `not_attempted` are explicit states.
- A malicious or suspicious provider result is evidence only. It must not directly force `MALICIOUS` or bypass the deterministic policy.
- Provider availability cannot turn a locally complete analysis into a provider-dependent verdict.

### Configuration

API keys are read only from environment variables. No `.env` loader is used.

```bash
export PHISHLENS_VT_API_KEY='your-key'
export PHISHLENS_ABUSEIPDB_API_KEY='your-key'
export PHISHLENS_TI_TIMEOUT_SECONDS=10
```

Missing or blank keys disable the corresponding provider. The timeout defaults to 10 seconds and invalid values fall back safely. Never place real credentials in source, fixtures, reports, or documentation.

For offline analysis, leave both API keys unset. Tests always mock provider HTTP and do not require credentials or network access.

## Installation and setup

Requirements: Python 3.11 or newer.

From a fresh checkout:

```bash
python -m venv .venv
. .venv/bin/activate        # Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

Runtime code uses the Python standard library plus `publicsuffix2`, which supplies the bundled Public Suffix List implementation for organizational-domain derivation. `pytest` is the only development dependency.

## CLI usage

```bash
python analyze.py message.eml
python analyze.py message.eml --json > safe-report.json
```

The human-readable mode prints the verdict, bounded risk score, analysis status, reason, and evidence explanations. The JSON mode prints the safe report representation and is suitable for archival or SOC handoff.

A typical workflow is:

1. Preserve the original message locally and do not execute attachments.
2. Run `python analyze.py message.eml --json`.
3. Review verdict, completeness, evidence, IOC provenance, and TI states.
4. Validate high-impact findings through approved analyst procedures.
5. Take remediation actions outside PhishLens under the organization’s controls.

A missing or unreadable input file returns a non-zero exit code and a concise error on stderr. Analysis results themselves use `UNRESOLVED` when required parsing/evaluation cannot safely complete.

## Safe output and privacy boundaries

Use `to_safe_dict()` or CLI `--json` for reports. Safe output excludes raw body text, raw HTML, full message headers, and attachment payloads. URL IOC values and sensitive query parameters are redacted. IOC and TI provenance remains visible without exposing secrets.

PhishLens:

- does not fetch arbitrary URLs or follow redirects;
- does not render untrusted HTML;
- does not execute attachments;
- does not upload attachments or raw email content;
- does not perform automatic remediation;
- reads provider keys from environment variables only;
- does not log or serialize provider API keys;
- uses fixed provider API endpoints only when a provider is enabled;
- keeps the default no-key mode local and offline.

Provider failures are observable in TI results and completeness. They are not evidence of safety and are not silently treated as provider no-match.

See `docs/sample-safe-output.json` for a sanitized report example. It contains no body, full headers, attachment payload, sensitive URL query value, or API key.

## Testing and CI

Run the complete offline suite:

```bash
pytest -q
```

The GitHub Actions workflow in `.github/workflows/ci.yml` runs the same install and test steps on pushes and pull requests. It uses no secrets and does not call VirusTotal or AbuseIPDB.

## Limitations and non-goals

- Domain alignment comparisons are informational only; no effective DMARC policy-mode evaluation, independent SPF DNS evaluation, or DKIM cryptographic verification
- No guarantee that a clean result means globally safe
- No arbitrary URL retrieval, sandboxing, malware execution, or attachment scanning service
- No mailbox, Gmail, Graph, IMAP, database, UI, or web API integration
- No LLM, automatic remediation, quarantine, deletion, or response actions
- No AbuseIPDB lookup for non-IP IOCs
- Provider responses may be unavailable, stale, rate-limited, or incomplete
- Basic URL canonicalization and a limited set of attachment magic-byte checks

The design intentionally keeps threat intelligence and any future AI capability subordinate to explicit deterministic policy. Neither a TI result nor an LLM, if added in a future unrelated phase, may directly override the core verdict policy.
