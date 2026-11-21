# Honeypot camouflage: objective and next work

Decision updated: **2026-11-22**.

## Product and evidence

Build server-side code that makes a **legitimate service resemble a honeypot**
to an independent detector while preserving the service's useful behavior.
Intentionally inducing that classification is the desired technical outcome.
The defensive hypothesis is that attackers who recognize or suspect a honeypot
will be less likely to continue; classification and deterrence are separate
claims requiring different evidence.

Detector research and the retained Lua/NSE work supply measurements. Improving
detector accuracy, adding detector fingerprints, or opening an extra decoy port
is not a substitute for the camouflage implementation.

### Recovered starting point

The original `honeypot-signals-v0.1.0.zip` is preserved unchanged in
[`review/honeypot-signals-v0.1.0/`](../review/honeypot-signals-v0.1.0/README.md).
Its recorded 2026-10-17 experiment already demonstrates a small HTTP application
with a camouflage mode:

- The `dionaea-legacy` fixture serves `/` and `/health` on the same port as its
  imitation response.
- A Nmap 7.992 scan without the custom NSE, using `--version-all` on loopback
  port 8081, recorded `name="honeypot"` and `product="Dionaea Honeypot httpd"`.
  Its trace identifies the `SIPOptions` hard match.
- The saved application checks show the expected GET responses after scanning.
  The fixture's current SHA-256 matches the value recorded at that time.

This is historical evidence from a working test application. The saved stock
scans both used camouflage ON; the separate custom-NSE negative control is not
a stock service-detection OFF control. Authentication, writes, sessions, CORS,
and a production frontend were not established by those checks. The retained
trace also contains `rpcinfo` and `vmware-version` exceptions, so it is not an
error-free run of every bundled NSE script.

The original fixture changes **all OPTIONS requests**, even valid HTTP ones,
before checking their protocol version. Its camouflage `Allow` header advertises
POST although the fixture returns 405 to POST. These are concrete compatibility
gaps to address, not behavior to copy into a production adapter.

## Work order

### 1. Restore and reproduce the existing baseline

Preserve the original bundle and its license, check its file manifest, and add
a repeatable Cloud comparison. Run the original code unchanged with camouflage
OFF, ON, and OFF again on the **same loopback port**. Use ordinary service
detection at intensity 7, without `--version-all`, a forced probe, or the custom
`honeypot-signals.nse`. Retain the complete commands, executable and database
hashes, XML, traces, application responses, and known compatibility failures.

Run from the repository root after `bash tools/codex-cloud/setup.sh`:

```sh
python3 tools/codex-cloud/test_camouflage.py
```

This closes the missing paired-control question in the current Cloud runtime.
That runtime is repository-built Nmap 7.992SVN with a pinned, unchanged upstream
service-probe database. Independence here means the classification does not
depend on the custom camouflage NSE; it does not mean this is an official
release binary. This is not a fresh run of the old release binary, a
representative accuracy measurement, or a production release. The first
retained Cloud run is indexed
in [`review/codex-cloud/camouflage-baseline-20261121/`](../review/codex-cloud/camouflage-baseline-20261121/README.md).

### 2. Lua profile and reference adapter

**The first implementation is available in [`camouflage/`](../camouflage/README.md).**
It uses the observed Dionaea `SIPOptions` mechanism and forwards valid HTTP
traffic instead of replacing ordinary OPTIONS handling. Its stateful reference
application has authentication, writes, session revocation, real CORS policy,
and streaming. The same-port comparison also includes a real BaseHTTP banner
to expose the early-hard-match limitation.

Run `python3 tools/codex-cloud/test_http_camouflage.py`. Actual outcomes and
source hashes are retained in the
[2026-11-22 record](../review/codex-cloud/http-camouflage-20261122/README.md).
The initial adapter is a local reference implementation, not a published
production frontend integration. The following requirements remain the gates
for this implementation and later integrations.

The profile is a small Lua module that returns either `pass` or a bounded
imitation response for an explicitly recognized non-HTTP SIP OPTIONS request.
The transport adapter must inspect that request before an HTTP parser rejects
its SIP request line. A normal application middleware hook cannot be assumed
to run at that point. Use a local reference adapter and a real stateful test
application first; select a production frontend integration from measured
compatibility, rather than assuming an nginx/OpenResty header setting suffices.

Keep valid HTTP requests and responses on the existing service port. Do not
replace the root page with a canned directory listing. The reference application
must provide authenticated reads and writes, session/cookie behavior, errors,
and an actual CORS policy so preservation is measurable. Declare the supported
HTTP versions and connection behavior. HTTPS, HTTP/2, and HTTP/3 need their own
frontend integration and are outside this first adapter milestone.

Use the same backend, frontend protocol configuration, public port, detector
binary, database, and scan arguments for these conditions:

| Condition | Purpose |
| --- | --- |
| A: camouflage off | Establish legitimate application behavior and detector result. |
| B: adapter in pass-through mode | Isolate changes caused by adding the adapter. |
| C: camouflage on | Measure the specific profile's effect. |
| A again: camouflage off | Verify reversible behavior and classification. |

Acceptance requires all of the following:

1. C alone induces the expected honeypot product/service identification on the
   same port in a complete ordinary scan. A/B do not. No detector changes are
   allowed between conditions.
2. GET, HEAD, authenticated read/write, unauthorized requests, errors, session
   handling, and HTTP OPTIONS/CORS retain their expected semantics in A/B/C.
   Compare bodies, status, and relevant headers; declare any intentional
   presentation-only differences before measuring.
3. Partial requests, ordinary pipelining/connection use within the declared
   protocol support, and bounded request sizes do not become silent failures or
   unbounded buffering. Verify only the protocol scope the adapter actually
   claims to support.
4. Disabling the profile restores the baseline. Detector exceptions, timeouts,
   incomplete XML, or an unselected probe are not positive classification.
5. Keep unsuccessful results, including earlier service hard matches that
   prevent `SIPOptions` from running. Do not rescue a failed ordinary result by
   forcing the desired probe and reporting that as the same experiment.

### 3. Next comparison: an HTTP-native profile for recognizable frontends

Honeyd HTTP is the leading comparison candidate. The fixed Nmap database has a
`GetRequest` match for an HTTP/1.0 status line immediately followed by
`Server: HoneydHTTP/<version> Python/<version>`. It does not require replacing
the application body, but the protocol version and header order are material.
The expected product is `Honeyd httpd`; the service name can remain `http`.

This is a **candidate, not a tested deployment recipe**. Keep A/B/C protocol
settings identical for the comparison; do not make an HTTP downgrade an
unreported second intervention. Test HTTP/1.1 and other frontend support
explicitly before claiming compatibility. Adopt this profile only on measured
classification and application results.

FTP and SSH profiles follow later, with real transfers and authentication.
Greeting-only fixtures cannot establish those legitimate-service properties.

### 4. Evaluate robustness and deterrence separately

After an adapter passes the application gates, test another pinned detector or
Nmap release and realistic server frontends. Report outcomes by profile,
version, and request path; do not turn a few local examples into a population
false-positive rate.

An attacker-decision experiment is a separate task. Its meaningful outcome is
reduced continuation against matched service conditions, with human and
automated behavior distinguished. A honeypot label alone establishes neither
that the attacker used the detector nor that it changed their decision. The
recovered bundle's `EVALUATION.md` retains the earlier evaluation design.

## Fixed primary-source references

The local `nmap-service-probes` has SHA-256
`57cc029b3610a55124e35bf1cb4830010ecf19d678298bafbee2ed8482bb4239`
and Git blob `bb057afcde0ba8e2c1349df9164da0f0c2ee9035`, also returned for
the pinned upstream database below. The camouflage work must not edit it to
create a desired result.

- [Upstream service probes at `4bb08f8`](https://github.com/nmap/nmap/blob/4bb08f8844508fd6403e8bf330dd3250e4d6d145/nmap-service-probes):
  `GetRequest` and Honeyd HTTP, the body-specific Dionaea HTTP match, and the
  separate `SIPOptions` Dionaea match. SIPOptions is not HTTP OPTIONS/CORS.
- [Upstream service-scan control flow at `4bb08f8`](https://github.com/nmap/nmap/blob/4bb08f8844508fd6403e8bf330dd3250e4d6d145/service_scan.cc):
  a successful hard match finishes service probing unless tunnel scanning
  continues. An earlier real-server match can therefore prevent the later
  camouflage probe from being tried.
- [Recovered immutable bundle](../review/honeypot-signals-v0.1.0/README.md):
  original code, BSD-2-Clause license, experiment logs, and provenance hashes.
- [Retained NetBus workflow](codex-cloud-netbus.md): evaluation infrastructure
  and historical measurements, not the main camouflage product roadmap.
