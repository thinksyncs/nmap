# HTTP camouflage reproduction — 2026-11-21

The recovered Dionaea camouflage fixture produces a honeypot classification in
the current Cloud runtime, with the profile OFF/ON/OFF on the same loopback
port. **Reproduction passed; HTTP compatibility failed for ordinary OPTIONS.**
This is a small application experiment, not production-adapter acceptance or
an attacker-deterrence result.

## Results

The final run took place at **21:56:11–21:56:31 JST** on 2026-11-21
(12:56:11–12:56:31 UTC), approximately 20.5 seconds.

| Condition | Service result | Interpretation |
| --- | --- | --- |
| OFF before | `blackice-icecap`, `method=table`, `conf=3`, no product | Port-table fallback; product unclassified and no honeypot label. Not a positive identification of a normal server. |
| ON | `honeypot`, `product=Dionaea Honeypot httpd`, `method=probed` | `SIPOptions` hard match in the fixed service-probe database. |
| OFF after | Same classification attributes as OFF before | Disabling the profile restored baseline responses and classification. |

All three scans completed with exit status 0 and complete XML. No NSE execution
exceptions were found in their debug output. The unchanged full installed
script index was used; the runtime reported loading 48 version scripts. The
custom `honeypot-signals.nse` was not installed or selected. No forced probe or
`--version-all` was used.

For each condition, the harness sent five HTTP requests before and after the
scan: `GET /`, `GET /health`, `HEAD /`, `GET /missing`, and `OPTIONS /`.
These are **30 requests across five request types**, not 30 independent
applications or implementations. Responses were stable within every condition.
Across OFF and ON, the first four responses were byte-identical; only OPTIONS
changed:

| Response field | OFF | ON |
| --- | --- | --- |
| Status | `HTTP/1.1 204 No Content` | `HTTP/1.0 200 OK` |
| Allow | `GET, HEAD, OPTIONS` | `OPTIONS, GET, HEAD, POST` |

The fixture does not implement POST despite that advertised method. CORS,
authentication, stateful writes, sessions, and a production frontend were not
tested. The report deliberately contains both:

```json
{
  "reproduction_status": "pass",
  "off_on_http_compatibility": {
    "status": "fail",
    "differing_requests": ["options"]
  },
  "production_readiness": "not_established",
  "deterrence": "not_tested"
}
```

The harness's exit code 0 means that it reproduced the frozen baseline,
including this known incompatibility. It is not an application-preservation
gate for the next adapter.

## Runtime and fixed inputs

The runtime is **repository-built Nmap 7.992SVN**, with Lua 5.4.9 and without
OpenSSL/libssh2. It is not the official Nmap 7.992 release binary used in the
original October record. The Python harness ran under CPython 3.12.14.
Independence here means that the core service fingerprint does not depend on
the project's custom camouflage NSE.

| Input | SHA-256 |
| --- | --- |
| Nmap executable | `5cebac67aafcdc11f662c4fd82285da8c4bb368a31d3b5062f26c8023bfa171b` |
| Unchanged upstream service-probe database | `57cc029b3610a55124e35bf1cb4830010ecf19d678298bafbee2ed8482bb4239` |
| Full installed `script.db` | `6a7436ab3613d493900e6bc22d64f12a8c4decb829627f288623b8bc0e82d4c2` |
| Original ZIP | `a9a6d80faf6fc4093175ae9432b2ce74e1da031adbd251a6c778c1476fcd02f4` |
| Original HTTP fixture | `dfb695260ca1ce22716a4a6f33dc7908daa9fabc9759effd9b7d0e2b9834ccfa` |
| Executed harness | `d3a4499bb8f555066548db0aa25d0459007b99da26ed480c995000087db61313` |

The first five hashes were checked before and after the experiment and remained
unchanged. The harness hash and Python information were recorded after the run;
[`run-provenance.json`](run-provenance.json) explicitly labels that receipt and
records the last source modification time before execution. The original source
ZIP is preserved in [the recovered snapshot](../../honeypot-signals-v0.1.0/README.md).

## Commands and records

From the repository root, after preparing the Cloud runtime:

```sh
python3 tools/codex-cloud/test_camouflage.py
```

The default archive is the restored copy in `review/`. The measured invocation
used the byte-identical recovery copy via `--archive`; the exact argv is in the
provenance receipt. Every scan used the following form, with absolute paths in
the raw record:

```sh
.codex-cache/runtime/bin/nmap \
  --datadir .codex-cache/runtime/share/nmap \
  --unprivileged -sT -Pn -n -sV --version-intensity 7 \
  --version-trace -d1 -p 8081 -oA CASE_DIRECTORY/scan 127.0.0.1
```

- [`summary.json`](summary.json): unchanged final report, including raw service
  attributes, commands, hashes, and base64 request/response records.
- [`run-provenance.json`](run-provenance.json): execution and source receipt.
- [`validation.json`](validation.json): packaging checks and evidence inventory.
- [`results.tar.gz`](results.tar.gz): complete raw scan records for the initial
  attempt and final run, with a manifest. Original extracted source copies and
  runtime binaries are omitted; the frozen ZIP is distributed separately.
- [`SHA256SUMS`](SHA256SUMS): checksums for the report, receipt, validation record,
  and evidence archive.

### Initial harness expectation corrected

The first three scans completed, but the initial harness incorrectly required
OFF to have a `method=probed` HTTP identification. Both OFF scans instead fell
back to the port table. It therefore marked those controls as failures even
though they contained valid responses and complete service scans.

The final harness distinguishes a complete, unclassified no-honeypot-label
result from a missing or failed scan. It also checks that GetRequest and
SIPOptions were actually sent to the OFF control. A fresh OFF/ON/OFF run then
completed with that corrected expectation. Both sets of raw records are retained
in the archive; the earlier failure was not overwritten. The unstable timestamp
inside `servicefp` is excluded only from the restoration equality check; the raw
fingerprint is retained.

## Consequence for development

The next task is a Lua profile and adapter that preserves valid HTTP OPTIONS
while reproducing the non-HTTP SIPOptions response, followed by real application
compatibility tests. The baseline's OFF responses do not hard-match a real
server product. This result therefore does **not** show that camouflage works
when an earlier GET fingerprint identifies nginx, Apache, or another frontend
and prevents SIPOptions from being tried. Those are next-stage measured cases,
not assumptions. See [the roadmap](../../../docs/honeypot-camouflage-roadmap.md).
