# Recovered HTTP camouflage baseline

Recovered on **2026-11-21** from the original project artifact. The archive is
preserved byte for byte; this directory is an immutable historical source and
evidence snapshot, not the location for new implementation changes.

| Item | Value |
| --- | --- |
| Archive | [`honeypot-signals-v0.1.0.zip`](honeypot-signals-v0.1.0.zip) |
| Size | 40,366 bytes |
| SHA-256 | `a9a6d80faf6fc4093175ae9432b2ce74e1da031adbd251a6c778c1476fcd02f4` |
| Recorded experiment date | 2026-10-17 |
| License | BSD-2-Clause; original `LICENSE` retained inside the archive |
| Archive manifest | All 18 entries in `honeypot-signals/SHA256SUMS` verified during recovery |

## What the artifact contains

The original `examples/camouflage_lab.py` includes a small normal HTTP
application and an optional historical Dionaea-compatible OPTIONS response.
It also contains the Lua/NSE detector, tests, Japanese and English README files,
an evaluation plan, and raw Nmap records. The HTTP fixture SHA-256 is
`dfb695260ca1ce22716a4a6f33dc7908daa9fabc9759effd9b7d0e2b9834ccfa`,
matching the value in its original validation record.

The recorded stock Nmap 7.992 scan used `--version-all` against loopback port
8081 without the custom NSE. Its XML reports `name="honeypot"` and
`product="Dionaea Honeypot httpd"`; its trace identifies `SIPOptions` as the
hard match. The same fixture continued to serve the expected `/` and `/health`
GET responses. These are historical records, not a newly executed 7.992 run.

The two saved scan executions both have camouflage enabled. They compare
stock Nmap with stock Nmap plus a metadata-reading NSE, not camouflage OFF with
ON. Trace logs also retain `rpcinfo` and `vmware-version` errors. The old release
binary and probe database are not included; their original recorded hashes do
not by themselves re-verify those external files during this recovery.

## Compatibility gap retained as evidence

The original implementation handles every OPTIONS request before validating
HTTP versus SIP syntax. It consequently changes normal HTTP OPTIONS behavior,
and advertises POST in `Allow` even though POST returns 405. GET health checks
alone do not establish that a real application's CORS, authentication, or writes
survive camouflage. The SSH and DTK modes are greeting fixtures, not complete
legitimate SSH or application services.

Do not edit the archive to conceal these limitations. Add a separate Lua profile
and adapter according to [the project roadmap](../../docs/honeypot-camouflage-roadmap.md).

## Current Cloud reproduction

From the repository root:

```sh
bash tools/codex-cloud/setup.sh
python3 tools/codex-cloud/test_camouflage.py
```

The new harness verifies this archive, extracts the original code unchanged,
and records ordinary intensity-7 OFF/ON/OFF service scans on loopback port 8081.
Its application checks explicitly retain the OPTIONS incompatibility. It does
not install or select the archive's custom NSE to produce a positive result.
The current runtime is repository-built Nmap 7.992SVN with a pinned, unchanged
upstream service-probe database, not the official 7.992 release binary used by
the historical experiment.

The [2026-11-21 Cloud record](../codex-cloud/camouflage-baseline-20261121/README.md)
is a separate result with its own runtime and database hashes. For the original
experiment, inspect `VALIDATION.md`, `validation/stock.xml`,
`validation/stock-trace.log`, and `validation/independent-summary.json` inside
the archive.
