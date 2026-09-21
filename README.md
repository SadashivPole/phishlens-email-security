# PhishLens

PhishLens is a local-first, explainable email-security and SOC-triage foundation.

This initial phase analyzes `.eml` files without network access, external APIs, an LLM, a database, or cloud services.

## Current pipeline

```text
raw .eml
  -> safe parser
  -> normalized ParsedEmail
  -> local analysis modules
  -> EvidenceItems
  -> bounded scoring
  -> policy
  -> AnalysisResult
```

## Current capabilities

- RFC-style email and MIME parsing using Python's standard library
- Header extraction
- Authentication-Results parsing
- Informational DNS-context representation
- URL extraction and conservative normalization
- Display/href mismatch detection
- IP-literal and userinfo detection
- Attachment metadata and SHA-256 extraction
- Basic magic-byte and MIME mismatch detection
- Double-extension detection
- Provenance-backed evidence
- Bounded deterministic scoring
- CLEAN, SUSPICIOUS, MALICIOUS, and UNRESOLVED verdicts
- Offline CLI analysis

## Important policy

Local heuristic indicators such as suspicious URL structure, IP-literal URLs, URL encoding, Reply-To mismatch, and suspicious attachment metadata are not proof of maliciousness. They can produce a `SUSPICIOUS` verdict, but `MALICIOUS` requires an explicitly defined high-confidence hard indicator. The initial local-only foundation has no automatic malicious hard indicator, so it will not force `MALICIOUS` from weak local heuristics.

Missing evidence is not evidence of cleanliness. Analysis completeness is represented with explicit states such as `complete`, `partial`, `unavailable`, and `not_evaluable`; no arbitrary numeric coverage score is used.

Authentication-Results values are receiver-reported evidence. DNS record existence is informational context and never proves that a particular message passed SPF, DKIM, or DMARC.

## Requirements

- Python 3.11+
- `pytest` for tests

Runtime functionality uses only the Python standard library.

## Usage

```text
python analyze.py path/to/message.eml
python analyze.py path/to/message.eml --json
```

The analyzer does not fetch URLs, execute attachments, render untrusted HTML, or make network requests. Optional VirusTotal and AbuseIPDB configuration is read only from `PHISHLENS_VT_API_KEY` and `PHISHLENS_ABUSEIPDB_API_KEY`; Phase 3B.1 configures enabled providers but does not make API calls. `PHISHLENS_TI_TIMEOUT_SECONDS` controls the future request timeout and defaults safely to 10 seconds.

## Known limitations

- No independent SPF evaluation
- No DKIM cryptographic verification
- No DMARC alignment calculation
- No external reputation enrichment
- No ClamAV or sandbox integration
- No mailbox connectors
- No persistence
- No UI or web API
- Basic URL canonicalization only
- Magic-byte detection covers only a small initial set of types
