# Ordinary service-selection validation — 2026-11-17

The Cloud development runner now includes an `ordinary` suite in `--suite all`.
It uses real Nmap service detection and `--script netbus-version`, without a
forced port-rule match. This closes a coverage gap in the previous Cloud gate:
socket contracts mock the port rule, and forced replays cannot establish that
normal service selection executes the working script.

The NSE classification logic is unchanged. The tested script SHA-256 is
`1dab4ae5605d6830daade00ea7fe859ec9f9276f8ea85c9c86bc83a59e38b130`.

## Fresh execution results

The complete workflow exited 0 in 113.756 seconds. Its unmodified aggregate
report is [validation.json](validation.json).

| Check | Observed result |
| --- | --- |
| Working NSE contracts | 169 passed, zero failures |
| Forced response replays | 20 passed: 10 each for the 1.30 and 1.31 fixtures |
| Ordinary service selection | 24 passed: 12 each for the 1.30 and 1.31 fixtures |
| Ordinary positive results | Six expected identifications, including two versionless default Info results |
| Ordinary negative results | 18 retained the expected NetBus service name, product, and version |
| Synthetic comparison | 28 scans passed across seven conditions, including 14 warmups |
| Frozen review archive | 1,739 manifest files, patches, fixture checks, and snapshot contracts passed |
| Historical records | 136 synthetic and 168 Wine/QEMU application scans rechecked |

The ordinary inventory is `real_positive`, `real_negative`, `negative_denied`,
`split_7`, `response_eof_7`, `response_timeout_0`, `malformed_status`,
`other_version`, `info112_real`, `info112_altered`, `info112_eof_55`, and
`info112_timeout_55`. The common controls run in both fixture groups; the count
does not imply 24 distinct applications or independent deployment samples.

The wrapper checks the reported selection mode, candidate implementation,
complete ordered case inventory, per-case outcomes, exact live path and source
hash, and verified overlay before accepting the ordinary suite.

## Deliberate fault controls

Two temporary copies of the NSE were changed to confirm that ordinary mode
detects the failures it is intended to catch. Both controls exited 1 and were
reported as failures, which is the expected result for these faulty copies.
The working NSE and frozen harness were unchanged.

| Deliberate change | Case | Detected failure |
| --- | --- | --- |
| Port rule always returns false | `real_positive` | NSE never ran; no query connection; original NetBus metadata remained |
| Negative result overwritten with NetBuster metadata | `real_negative` | Negative service metadata changed to NetBuster |

[gate-controls.json](gate-controls.json) records the mutation hashes, commands,
exit codes, XML service metadata, and failure messages. These are two extra
control scans, separate from the 24 passing ordinary scans. Faulty source
copies are retained only inside the evidence archive for reproduction.

## Reproduce and inspect

From the Cloud development branch with its runtime prepared:

```sh
python3 tools/codex-cloud/test.py --suite ordinary
python3 tools/codex-cloud/test.py --suite all
```

[results.tar.gz](results.tar.gz) contains the fresh command/output logs, Nmap
XML, server events, suite reports, the tested wrapper and NSE source, and both
deliberately faulty control sources. It also includes the frozen-review
aggregate report. Historical raw application data remain in the original
unchanged review archive and are not duplicated here. Every retained file has
an entry in the archive's `MANIFEST.sha256`.

Verify the published evidence with:

```sh
sha256sum -c SHA256SUMS
tar -xzf results.tar.gz
(cd ordinary-selection-20261117 && sha256sum -c MANIFEST.sha256)
```

The aggregate report's `source_commit` is the checkout before committing this
runner change. Its `test_runner_sha256` identifies the exact tested working
wrapper. The Nmap engine was reused from the successful source build at
`1aa2aaa7ae695bed2f89c2e475f6e003e52b97fb`; no engine source changed. Runtime:
Nmap 7.992SVN, Lua 5.4.9, Python 3.12.14, Linux x86-64.

## Scope

All fresh network tests used loopback fixture servers. Ordinary mode indexes
only `netbus-version` and retains the original service probes; it does not test
interactions with the entire NSE script collection. These checks establish
behavior for the selected fixtures and transport cases, not a real-world
false-positive rate or attacker deterrence effect.

No new NetBuster/NetBus application measurements ran. Stored Wine/QEMU data
were rechecked, and native Windows remains outside this validation. The local
runtime omits OpenSSL and libssh2. The frozen
[`review/netbus-multiversion/`](../../netbus-multiversion/README.md) snapshot
retains its original bytes and checksums.
