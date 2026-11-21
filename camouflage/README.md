# Lua honeypot camouflage for an HTTP service

This reference implementation places a **Lua presentation profile** in front of
a working HTTP application. It answers a narrowly recognized non-HTTP SIP
OPTIONS request with a historical Dionaea response. Valid HTTP traffic is
forwarded unchanged, including normal OPTIONS and CORS preflight requests.

The profile is server-side code. The independent classification experiment uses
the existing Nmap service-probe database without editing it or adding a custom
NSE fingerprint. This is a plaintext, IPv4 loopback implementation for developing
and measuring the technique. Attacker deterrence is a separate, untested claim.

## Files

| File | Responsibility |
| --- | --- |
| [`lua/dionaea_sip.lua`](lua/dionaea_sip.lua) | Pure Lua decision and bounded imitation response. |
| [`lua/decide.lua`](lua/decide.lua) | Small stdin/stdout bridge to an ordinary Lua interpreter. |
| [`adapter.py`](adapter.py) | TCP prefix inspection and transparent bidirectional forwarding. |
| [`reference_app.py`](reference_app.py) | Stateful application with login, session revocation, reads/writes, CORS, and streaming. |
| [`tests/test_profile.lua`](tests/test_profile.lua) | HTTP/SIP boundary and incomplete-input checks. |
| [`../tools/codex-cloud/test_http_camouflage.py`](../tools/codex-cloud/test_http_camouflage.py) | Same-port application and ordinary Nmap comparison. |

## Run the reference application and adapter

Python 3.9+ and Lua 5.4 are sufficient for the two runtime components. The
repository's prepared runtime supplies Lua and Nmap for the experiment:

```sh
bash tools/codex-cloud/setup.sh
```

Start the application in one terminal:

```sh
python3 camouflage/reference_app.py --port 18081 --presentation generic
```

Start the adapter in another terminal:

```sh
python3 camouflage/adapter.py \
  --listen-port 8081 --backend-port 18081 --mode dionaea-sip
```

Both processes bind `127.0.0.1`. To use another Lua installation, pass
`--lua /absolute/path/to/lua` to the adapter. Use `--mode passthrough` to keep
the same transport path with imitation disabled. The backend port must differ
from the listener port. Existing listeners are never stopped or replaced.

Examples of ordinary application operations:

```sh
curl -i http://127.0.0.1:8081/health
curl -i -X OPTIONS http://127.0.0.1:8081/state \
  -H 'Origin: https://client.example.test' \
  -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: Content-Type'
```

The published local test account is `alice` / `local-test-password`.
`POST /login` accepts a JSON object with `username` and `password` and issues an
opaque session cookie. Use that cookie for `GET /state`, `PUT /state` with a
JSON `value`, and `POST /logout`. Logout invalidates the session. This reference
account and in-memory store are test application components.

## Lua interface

```lua
local profile = dofile("camouflage/lua/dionaea_sip.lua")
local result = profile.decide("OPTIONS sip:nm SIP/2.0\r\n")
-- result.action == "reply"; result.response contains the fixed wire response.

local normal = profile.decide("OPTIONS /state HTTP/1.1\r\n")
-- normal.action == "pass"; the application's response is retained.
```

The accepted line is uppercase `OPTIONS`, one space, a nonempty printable ASCII
`sip:` or `sips:` URI, one space, `SIP/2.0`, and CRLF. This is deliberately a
limited profile, not a complete SIP parser. Incomplete lines, unsupported
syntax, and inputs beyond 8 KiB return `pass`.

The adapter inspects only the **first request line of a TCP connection**. It
bypasses noncandidate prefixes early. After a pass decision, all bytes in both
directions are relayed without further parsing, including already buffered
headers and bodies, keepalive requests, pipelined requests, and chunk framing.
A SIP-looking string inside an HTTP body does not change that decision. A
later SIP request on an already forwarded connection is not intercepted.

The profile's historical response advertises POST as part of its fixed
fingerprint. That response is sent only on the non-HTTP SIP path. Ordinary HTTP
OPTIONS obtains the real application's method list, rather than that legacy
advertisement.

## Transport bounds and failure behavior

| Property | Default |
| --- | --- |
| Candidate prefix | At most 8 KiB |
| Initial prefix deadline | 10 seconds |
| Lua process deadline | 1 second |
| Backend connection deadline | 3 seconds |
| Relay idle deadline | 30 seconds |
| Relay buffers | At most 64 KiB per direction |
| Active connections | At most 32 |

Prefix overflow or expiry forwards the bytes already received to the backend.
A Lua execution failure also bypasses the profile and increments `policy_errors`.
The fixed driver is executed with `lua -E` and no shell; request bytes are never
Lua source or filenames. Missing Lua is an explicit startup error in active
mode. Backend failures and capacity rejection have separate counters.

The adapter handles partial writes, backpressure, and half-close. After sending
an imitation response it closes its write side and drains a bounded header
tail, allowing split SIP probes to receive the whole response. Shutdown closes
remaining connections. These bounds are part of the reference implementation;
they do not establish production throughput or availability properties.

## Application and classification experiment

Stop the manual demo listeners before running the comparison, which owns its
own temporary application instances and the same loopback port 8081:

```sh
.codex-cache/runtime/bin/lua -E camouflage/tests/test_profile.lua
python3 tools/codex-cloud/test_http_camouflage.py
```

Every output directory is fresh. The harness compares:

| Condition | Public port | Application path |
| --- | --- | --- |
| A: direct | 8081 | Reference application directly. |
| B: pass-through | 8081 | Same application code/configuration through the identity adapter. |
| C: active | 8081 | Same adapter with the Lua profile enabled. |
| A restored | 8081 | Direct application again. |

Each instance starts with identical application state. B/C use a separate
ephemeral backend port; only port 8081 is scanned. The detector binary, probe
database, full script index, scan settings, and application presentation stay
fixed within each group. Session tokens and Date values are the only normalized
response fields; their presence and cookie attributes remain part of comparison.

The experiment has two presentation groups:

- `generic` omits the Server banner and retains Date in both OFF and ON conditions. This tests
  whether the narrow SIP profile can induce a Dionaea label while preserving
  the working application.
- `basehttp` exposes the actual Python standard-library Server header. Its
  expected early GetRequest hard match is a **negative efficacy control**: a
  later forced SIP request must not be used to claim that ordinary Nmap
  camouflage succeeded.

The application checks cover authentication and refusal, state mutation and
retention across scanning, session revocation, normal OPTIONS/CORS, error bodies,
large binary echo with SIP text inside the body, chunked response streaming,
segmented/pipelined requests, `100 Continue`, half-close, and prefix-limit bypass.
The reference app accepts Content-Length request bodies and explicitly rejects
chunked requests; transparent forwarding does not add backend capabilities.

HTTP/1.0 and HTTP/1.1 behavior is measured within these application bounds.
TLS termination, HTTP/2, HTTP/3, arbitrary nginx/Apache integrations, and public
deployment are separate work. No response protocol downgrade or HTTP body
replacement is performed by this adapter.

See the [2026-11-22 measured record](../review/codex-cloud/http-camouflage-20261122/README.md)
and the [project roadmap](../docs/honeypot-camouflage-roadmap.md) for actual
outcomes and subsequent work. A successful overall harness result includes the
expected BaseHTTP efficacy failure; the report records it separately.

## License

The new runtime code and profile tests in this directory are available under
the [BSD-2-Clause license](LICENSE), consistent with the recovered camouflage
bundle. Nmap and files outside this directory retain their respective licenses.
