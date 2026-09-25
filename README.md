# PhishLens

PhishLens is a local-first, explainable email-analysis tool for SOC triage. It turns an `.eml` message into a bounded risk score, a cautious verdict, explicit per-area completeness states, IOC records, and provenance-backed evidence. All local detection and scoring is deterministic; optional VirusTotal and AbuseIPDB lookups add evidence records without changing the verdict or the score.

Current version: 1.1.0 (`pyproject.toml`, git tag `v1.1.0`). License: MIT (`LICENSE`).

## What problem it solves

A SOC analyst often needs a fast first-pass answer without uploading a potentially sensitive message to an external service. PhishLens provides a reproducible local analysis of identity, authentication, URLs, content, mail flow, attachments, and optional threat-intelligence observations. It is designed to explain what was observed and what could not be evaluated; it is not an autonomous incident-response system.

## Architecture and data flow

```text
.eml bytes
  -> bounded stdlib MIME parser (email-size, attachment-size, and MIME-part limits)
  -> ParsedEmail and attachment metadata (SHA-256 hash, magic-byte type detection)
  -> deterministic local analyzers
       identity/authentication headers, Received mail flow, URLs, content, attachments
  -> IOC extraction and normalization (IP, domain, URL, SHA-256)
  -> optional provider orchestration
       VirusTotal and AbuseIPDB, enabled only by environment variables
  -> normalized ThreatIntelResult records
  -> bounded threat-intelligence evidence records
  -> deterministic scoring and verdict policy
  -> AnalysisResult / safe JSON report
```

Module map (all under `src/phishlens/`):

|Area|Modules|Role|
|-|-|-|
|Parsing|`parsing/eml_parser.py`, `parsing/headers.py`, `parsing/authentication.py`, `parsing/domain_alignment.py`|Bounded stdlib MIME parsing; identity, Received, and Authentication-Results analysis; SPF/DKIM domain comparison|
|Analysis|`analysis/url_analysis.py`, `analysis/content_analysis.py`, `analysis/attachment_analysis.py`|URL heuristics, content-language heuristics, attachment metadata checks|
|Extraction|`extractor/ioc_extractor.py`|IOC extraction, normalization, and provenance|
|Enrichment|`enrichment/base.py`, `configured.py`, `orchestrator.py`, `virustotal.py`, `abuseipdb.py`, `mock_provider.py`|Provider protocol, orchestrator, VirusTotal v3 and AbuseIPDB v2 GET-only adapters, deterministic mock provider|
|Scoring|`scoring/rule_engine.py`, `scoring/policy.py`, `scoring/threat_intel_policy.py`|Capped per-category scoring, verdict policy, threat-intelligence evidence bounding|
|Pipeline|`pipeline/analyzer.py`|Wires parsing, analysis, extraction, enrichment, and scoring together|
|CLI|`analyze.py` (repository root)|Command-line entry point|
|Models|`models/` (email, evidence, indicators, ioc, result, scoring, threat_intel, verdict)|Shared dataclasses and safe serialization|

Properties of the pipeline:

* All local detection and scoring is deterministic.
* Provider results are evidence records only. In this release they neither change the verdict nor contribute points to the numeric score (see "Threat intelligence").
* LLM output is not used anywhere in the pipeline.

Authentication alignment is informational. PhishLens compares the visible From domain with the SPF and DKIM domains asserted by received Authentication-Results headers (SPF via `smtp.mailfrom`, DKIM via `header.d`/`d`). It reports strict equality and relaxed equality (organizational-domain equality, using the Public Suffix List data bundled with `publicsuffix2`), but it does not know the effective DMARC alignment mode and therefore reports effective alignment as `unknown`. These comparisons do not independently evaluate SPF DNS policy or verify DKIM signatures.

## Verdicts and scoring

The verdict policy applies in this order (first match wins):

1. **MALICIOUS** - requires a high-confidence hard indicator. No hard indicators are defined in this release, so no analyzer or provider result can produce `MALICIOUS` in v1.1.0. The mechanism exists for future, explicitly defined indicators.
2. **SUSPICIOUS** - local evidence is materially concerning: one high-severity material finding, two or more medium-severity material findings, or a total score of at least 10 together with a material finding.
3. **UNRESOLVED** - a required local analysis area (parser, identity, authentication, URL, or attachment) could not be safely evaluated - for example malformed input, missing Authentication-Results evidence, or a URL candidate that could not be normalized - and no material suspicious evidence was found. Note the precedence: material suspicious evidence yields `SUSPICIOUS` even when required analysis is incomplete; the incomplete state remains visible in `analysis_status` and in the `completeness` block.
4. **CLEAN** - required local analysis completed without material suspicious evidence. This does not prove global safety.

Scoring:

* Per-category caps: authentication 20, identity 10, URL 20, attachment 15, content 5.
* The total score is the sum of the capped category scores, so the maximum achievable score is 70. The CLI prints the score with an `/100` label; the effective maximum under current caps is 70.
* Risk bands: `high` for scores of 30 and above, `medium` for 10-29, `low` below 10.
* Repeated evidence with the same category and signal ID is scored once.

Provider timeout, rate-limit, error, unavailable, and partial states remain explicit TI evidence. They do not silently become `no_match`, and they do not replace a normal local verdict with `UNRESOLVED` when required local analysis is otherwise complete (threat intelligence is an optional completeness area).

## Threat intelligence

Threat intelligence is optional and isolated from deterministic local scoring.

* **VirusTotal** (v3 API, GET requests only): IP, domain, URL, and SHA-256 file-hash lookups.
* **AbuseIPDB** (v2 `check` API): IP lookups only. Other IOC types return an explicit unsupported/unavailable result without making a request.
* Results are normalized to `ThreatIntelResult` records with provider, IOC type and value, status, disposition, confidence, provenance, and observed indicators.
* Explicit provider states: `match`, `no_match`, `partial`, `timeout`, `rate_limited`, `error`, `unavailable`, and `not_attempted` (used when no provider is enabled).
* TI evidence is deduplicated per provider and IOC and bounded to at most 10 points in total by the deterministic TI policy.
* In this release, TI evidence points are not included in the numeric score (the capped scoring categories are the five local categories only), and no TI signal can trigger `SUSPICIOUS` or `MALICIOUS`. A malicious or suspicious provider result is recorded as evidence for the analyst; it cannot change the verdict.
* Provider availability cannot turn a locally complete analysis into a provider-dependent verdict.

What is transmitted when a provider is enabled: the normalized IOC values only - IP addresses, domains, full URLs (including their query strings), and SHA-256 hashes - are sent to that provider's fixed API endpoint (`https://www.virustotal.com/api/v3` or `https://api.abuseipdb.com/api/v2/check`). Message bodies, headers, and attachments are never transmitted. If URLs in your messages may contain sensitive query parameters, keep providers disabled or review this boundary before enabling them.

### Configuration

API keys and limits are read only from environment variables when `Settings()` is constructed. No `.env` loader is used; `.env.example` is an inert template listing the supported variables.

|Variable|Default|Behavior|
|-|-|-|
|`PHISHLENS_VT_API_KEY`|unset|Enables the VirusTotal adapter when set to a non-blank value.|
|`PHISHLENS_ABUSEIPDB_API_KEY`|unset|Enables the AbuseIPDB adapter when set to a non-blank value.|
|`PHISHLENS_TI_TIMEOUT_SECONDS`|10|Per-request timeout in seconds. Invalid, zero, or non-finite values fall back to the default.|
|`PHISHLENS_MAX_EMAIL_BYTES`|10485760 (10 MiB)|Larger inputs fail parsing and produce `UNRESOLVED`. Invalid or non-positive values fall back to the default.|
|`PHISHLENS_MAX_ATTACHMENT_BYTES`|5242880 (5 MiB)|Larger attachments fail parsing and produce `UNRESOLVED`. Invalid or non-positive values fall back to the default.|
|`PHISHLENS_AUTH_RESULTS_MODE`|`raw`|`raw` treats message-supplied Authentication-Results as untrusted informational assertions. `trusted_ingress` is an explicit opt-in for messages received through a controlled, header-sanitizing ingress. Invalid values fall back to `raw`.|
|`PHISHLENS_TRUSTED_AUTHSERV_ID`|unset|Exact authserv-id selector used only in `trusted_ingress` mode. It does not prove header provenance; exactly one matching header is required.|

```bash
export PHISHLENS_VT_API_KEY='your-key'
export PHISHLENS_ABUSEIPDB_API_KEY='your-key'
export PHISHLENS_TI_TIMEOUT_SECONDS=10
export PHISHLENS_AUTH_RESULTS_MODE=raw
# Only for input from a controlled ingress that removes untrusted copies:
# export PHISHLENS_AUTH_RESULTS_MODE=trusted_ingress
# export PHISHLENS_TRUSTED_AUTHSERV_ID=mx.example.net
```

For arbitrary raw `.eml` input, Authentication-Results is attacker-controlled message data. Raw mode parses assertions only for low-reliability analyst visibility; they cannot complete required authentication analysis, add authentication-derived score, or create authoritative alignment conclusions. Trusted-ingress mode is a caller/operator assertion that a controlled mail boundary removed untrusted Authentication-Results headers before adding its own. Exact authserv-id matching selects that assertion but does not prove provenance or independently verify SPF, DKIM, DMARC, or ARC. Missing, nonmatching, or duplicate matching trusted headers fail closed.

Missing or blank keys disable the corresponding provider. For offline analysis, leave both API keys unset. Never place real credentials in source, fixtures, reports, or documentation. The MIME part limit (100 parts) is fixed in code and is not environment-configurable.

## Installation and setup

Requirements: Python 3.11 or newer (CI runs on Python 3.11). From a fresh checkout:

```bash
python -m venv .venv
. .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

Runtime code uses the Python standard library plus `publicsuffix2`, which supplies the bundled Public Suffix List data used for organizational-domain derivation. `pytest` is the only development dependency.

## CLI usage

From the repository checkout (the script imports the `src.phishlens` package):

```bash
python analyze.py message.eml
python analyze.py message.eml --json > safe-report.json
```

* Human-readable mode prints the verdict, risk score, analysis status, reason, and the explanation of every evidence item (including informational findings).
* JSON mode prints the safe report representation (`to_safe_dict()`; report `schema_version` is `1.0`) and is suitable for archival or SOC handoff.
* A completed analysis exits with code 0 whatever the verdict. A missing or unreadable input file exits with code 2 and a concise error on stderr.
* An email larger than `PHISHLENS_MAX_EMAIL_BYTES`, or containing an attachment larger than `PHISHLENS_MAX_ATTACHMENT_BYTES`, produces `UNRESOLVED` with a parse-failure reason.

Example results from the bundled fixtures (`tests/fixtures/`):

```text
phishing.eml  -> VERDICT: SUSPICIOUS, RISK SCORE: 26, ANALYSIS STATUS: complete
clean.eml     -> VERDICT: CLEAN, RISK SCORE: 0, ANALYSIS STATUS: complete
malformed.eml -> VERDICT: UNRESOLVED, RISK SCORE: 0, ANALYSIS STATUS: unavailable
```

A typical workflow is:

1. Preserve the original message locally and do not execute attachments.
2. Run `python analyze.py message.eml --json`.
3. Review verdict, completeness, evidence, IOC provenance, and TI states.
4. Validate high-impact findings through approved analyst procedures.
5. Take remediation actions outside PhishLens under the organization's controls.

## Safe output and privacy boundaries

Use `to_safe_dict()` or CLI `--json` for reports. Safe output excludes raw body text, raw HTML, full message headers, and attachment payloads. It includes selected metadata (From/To/Cc/Reply-To/Subject/Date/Message-ID, message size, attachment count), attachment metadata with SHA-256 hashes, redacted URL indicators, evidence, scoring, completeness, verdict, errors, IOCs, and threat-intelligence results. URL IOC values are redacted, and sensitive query parameters (for example `token`, `password`, or `key`) are replaced with `[REDACTED]`. IOC and TI provenance remains visible without exposing secrets.

PhishLens:

* does not fetch arbitrary URLs or follow redirects;
* does not render untrusted HTML;
* does not execute attachments;
* does not upload attachments or raw email content;
* does not perform automatic remediation;
* reads provider keys from environment variables only;
* does not log or serialize provider API keys;
* uses fixed provider API endpoints only when a provider is enabled;
* keeps the default no-key mode local and offline.

Provider failures are observable in TI results and completeness. They are not evidence of safety and are not silently treated as provider no-match.

See `docs/sample-safe-output.json` for a sanitized report example. It contains no body, full headers, attachment payload, sensitive URL query value, or API key. The sample was generated with an earlier release; current v1.1.0 output additionally includes SPF/DKIM alignment evidence items.

## Testing and CI

Run the complete offline suite:

```bash
pytest -q
```

The test suite comprises 143 tests across 20 test modules under `tests/`, with 14 `.eml` fixtures. It covers parsing, header and authentication analysis, domain alignment, URL/content/attachment analysis, IOC extraction, provider adapters and wiring, scoring policy, end-to-end fixtures, release readiness, and CLI behavior. Provider HTTP requests are always injected or monkeypatched, so no test performs external network access or requires credentials. One test patches `socket.socket` to fail if any network connection is attempted. A release-readiness test also verifies that this README retains its required contract sections and that the CI workflow remains offline and secret-free.



The GitHub Actions workflow in `.github/workflows/ci.yml` (named `PhishLens CI`) runs on pushes and pull requests. It checks out the repository, uses Python 3.11 on `ubuntu-latest`, installs the project with `python -m pip install -e '.[dev]'`, and runs `pytest -q` with both API-key environment variables set to empty strings. The workflow uses no secrets and does not make requests to VirusTotal or AbuseIPDB.

## Repository layout

```text
analyze.py                  CLI entry point
pyproject.toml              packaging, dependencies, pytest config
.env.example                inert template of supported environment variables
docs/sample-safe-output.json    sanitized example report
src/phishlens/              package source (see module map above)
tests/                      offline test suite and .eml fixtures
.github/workflows/ci.yml    GitHub Actions CI
```

## Limitations and non-goals

* No hard indicators are defined in this release, so `MALICIOUS` cannot be produced by the shipped analyzers or by provider results.
* Threat-intelligence results cannot change the verdict or the numeric score in this release; they are recorded as evidence only.
* Domain alignment comparisons are informational only: no effective DMARC policy-mode evaluation, no independent SPF DNS evaluation, and no DKIM cryptographic verification.
* No guarantee that a CLEAN result means globally safe.
* No arbitrary URL retrieval, sandboxing, malware execution, or attachment scanning service. Attachment checks are limited to filename and extension heuristics plus four magic-byte signatures (PE executable, PDF, ZIP/archive, OLE compound document).
* Basic URL canonicalization; a URL candidate that cannot be safely normalized marks URL analysis `partial`.
* Content analysis is a small set of regular-expression language heuristics (credential, urgency, payment, verification, call-to-action, and BEC patterns). Content is an optional completeness area - an empty body does not force `UNRESOLVED` - but content findings do contribute points and can trigger `SUSPICIOUS`.
* The `reputation` completeness area is a fixed placeholder that always reports `unavailable` in this release, even when TI providers are enabled; TI state is reported separately in the `threat_intelligence` area.
* No mailbox, Gmail, Graph, IMAP, database, UI, or web API integration; the only interface is the local CLI.
* No LLM, automatic remediation, quarantine, deletion, or response actions.
* No AbuseIPDB lookup for non-IP IOCs.
* Provider responses may be unavailable, stale, rate-limited, or incomplete.
* The CLI score label reads `/100` while the maximum achievable score under current category caps is 70.

The design intentionally keeps threat intelligence and any future AI capability subordinate to explicit deterministic policy. Neither a TI result nor an LLM, if added in a future phase, may directly override the core verdict policy.
