# Lua HTTP camouflage measurement — 2026-11-22

**The Lua profile induced a Dionaea classification while retaining the tested
application behavior in the generic frontend configuration. It did not induce
that classification when Nmap recognized the real BaseHTTPServer banner first.**
Both outcomes are retained. This record establishes a bounded reference adapter,
not general frontend compatibility or reduced attacker activity.

## Conditions and outcomes

The final experiment ran on **2026-11-22, 01:24:38–01:27:20 JST**
(2026-11-21, 16:24:38–16:27:20 UTC), approximately 161.7 seconds. All eight
ordinary service scans targeted the same IPv4 loopback port 8081.

| Presentation | A: direct app | B: pass-through adapter | C: Lua profile active | A restored |
| --- | --- | --- | --- | --- |
| Generic, no Server banner, Date retained | Product unclassified | Product unclassified | **Dionaea Honeypot httpd** | Product unclassified |
| Actual standard-library BaseHTTP banner | BaseHTTPServer | BaseHTTPServer | **BaseHTTPServer; camouflage ineffective** | BaseHTTPServer |

Generic OFF/B results use the port-table fallback `blackice-icecap`, with
`method=table` and no product. This is not a positive identification of a normal
server. The final harness requires GetRequest and SIPOptions to be sent to those
controls, so absence of a honeypot label is not attributed to an untried probe.

Generic C records `name=honeypot`, `product=Dionaea Honeypot httpd`, and
`method=probed`, with a SIPOptions hard match. For every BaseHTTP condition,
GetRequest hard-matches `BaseHTTPServer 0.6 / Python 3.12.14`; SIPOptions is not
sent in the service scan. C can answer a separate explicit SIP wire check, but
that check does not replace the unsuccessful ordinary-scan result.

The app code, starting state, port, and presentation are fixed within each
group. A binds the app directly to 8081; B/C use an ephemeral backend port and
keep the adapter at 8081. The comparator uses a fresh instance for each condition.

## Application preservation

Each condition ran **27 check types before and after scanning**, for 432 check
records across eight conditions. These are not 432 independent applications,
fingerprints, or even individual HTTP requests: the pipeline record contains
two requests. All twelve A-to-B/C/restored comparisons passed.

The checks include:

- GET, HEAD, health, 404, and an application 500 response.
- Failed and successful login, authenticated state reads and writes, refusal of
  unauthorized writes, and state retention across the scan.
- Random session-cookie issuance, attributes, logout, and rejected reuse of the
  revoked session.
- Normal HTTP OPTIONS, allowed CORS preflight, denied Origin, and refusal of a
  cross-origin state update without changing stored state.
- More than 256 KiB of binary echo containing the SIP probe string inside the
  HTTP body, plus a 256 KiB chunked HTTP/1.1 response.
- Large headers and a candidate-looking HTTP request line exceeding 8 KiB,
  verifying that bypass forwards the original request.
- Segmented pipelining, HTTP/1.0, client write-half-close, and `100 Continue`.

Only Date values and opaque session values in Set-Cookie are normalized across
runs. Header presence, cookie attributes, statuses, bodies, response versions,
and revocation behavior remain comparison inputs. Date is present in both
presentation modes. The normal application's 204 responses have no content and
no Content-Length, following [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6).

The previous frozen fixture's ordinary OPTIONS incompatibility is absent from
this adapter experiment. The legacy Allow header is now confined to the
non-HTTP SIP imitation response; the valid HTTP route returns its own method
list and CORS headers.

## Implementation and runtime

The source is in [`camouflage/`](../../../camouflage/README.md). Lua makes the
profile decision and supplies the fixed imitation bytes; the Python reference
adapter performs bounded TCP forwarding. It inspects only the first request
line, then passes the connection unchanged if the profile does not reply.

The profile tests passed **21 semantic cases and 24 incomplete-line boundary
checks** using the actual Lua interpreter. The same profile, adapter, app,
harness, Lua executable, Nmap executable, probe database, and script index were
hashed before and after the final experiment and remained unchanged.

| Input | Value |
| --- | --- |
| Nmap | Repository-built 7.992SVN; no OpenSSL/libssh2 |
| Lua | 5.4.9 |
| Python | CPython 3.12.14 |
| Nmap executable SHA-256 | `5cebac67aafcdc11f662c4fd82285da8c4bb368a31d3b5062f26c8023bfa171b` |
| Unchanged upstream probe DB SHA-256 | `57cc029b3610a55124e35bf1cb4830010ecf19d678298bafbee2ed8482bb4239` |
| Full installed script.db SHA-256 | `6a7436ab3613d493900e6bc22d64f12a8c4decb829627f288623b8bc0e82d4c2` |

The full installed version-script index was used. No custom camouflage NSE,
forced probe, `--version-all`, or detector database modification was used to
obtain the positive result. All eight scans completed with complete XML and no
recorded NSE execution failure. All adapter `policy_errors` counts were zero.
The raw counters also retain connection errors during scanner activity; this
record does not call the entire TCP experiment error-free. Metrics snapshots
are taken before context-manager shutdown.

## Reproduction and retained evidence

From the repository root with port 8081 free:

```sh
bash tools/codex-cloud/setup.sh
python3 tools/codex-cloud/test_http_camouflage.py
```

The final invocation used:

```sh
python3 -B tools/codex-cloud/test_http_camouflage.py \
  --output .codex-cache/http-camouflage-20261122/final
```

Each Nmap invocation used `--unprivileged -sT -Pn -n -sV --version-intensity 7
--version-trace -d1 -p 8081`, the fixed runtime data directory, and target
`127.0.0.1`. The full argv and raw output are retained per condition.

- [`validation.json`](validation.json) is the compact result index, including
  source/runtime hashes, per-condition classification, application comparisons,
  and verification of the packaged records.
- [`run-history.json`](run-history.json) separates the final run from preliminary
  work. An initial harness error tried to parse a plain-text 401 as JSON and
  stopped before Nmap. A subsequent complete preliminary run omitted Date in
  generic mode. The app was corrected to retain Date as required for ordinary
  responses from an origin with a clock; the final eight-case experiment was
  then run afresh. See [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1).
- [`results.tar.gz`](results.tar.gz) contains final and preliminary raw records,
  complete reports, commands, binary request/response artifacts, source receipts,
  and a byte-level manifest. The final executed source is under
  `http-camouflage-20261122/final/executed-source/` inside the archive.
- [`SHA256SUMS`](SHA256SUMS) covers the compact record, history, and archive.

## Practical boundary

The generic result shows that an independent fingerprint can be induced on a
stateful app without replacing normal HTTP responses. It does not show the
same effect for every existing server. The BaseHTTP negative result demonstrates
why an earlier service hard match matters, making an HTTP-native profile the
next comparison for recognizable frontends.

The current adapter is IPv4 loopback and plaintext only. The reference app
supports Content-Length request bodies and rejects chunked requests; the relay
does not add backend features. TLS termination, HTTP/2, HTTP/3, arbitrary proxy
integrations, production throughput, and attacker decisions remain outside this
measurement. See [the roadmap](../../../docs/honeypot-camouflage-roadmap.md).
