# Scan command and full-index validation — 2026-11-17

`tools/codex-cloud/scan.py` runs the working NetBus detector with an existing
Nmap executable. It uses a temporary overlay containing the candidate and an
unchanged copy of the full installed script index. It verifies selection and
identifies detector failures without modifying the existing installation.

The Lua detection fingerprints and retry logic are unchanged. The working NSE
SHA-256 remains
`1dab4ae5605d6830daade00ea7fe859ec9f9276f8ea85c9c86bc83a59e38b130`.

## Problems reproduced and addressed

**External path collision.** With an older installed copy,
`nmap -sV --script /another/path/netbus-version.nse` loads both the installed
version-category script and the explicitly named file. The retained control
exited nonzero with `duplicate script ID: 'netbus-version'` before making a
fixture query. The new command selects the overlay file by name and uses the
unfiltered index. Preflight verifies source selection; actual scans verify
that the full version-script collection can run.

**NSE failures hidden by successful Nmap exit.** An action exception or NSE
timeout can coexist with Nmap exit code 0 and successful run statistics. The
command retains level-one diagnostics and checks both target-script engine
diagnostics and XML error output. Such failures return a nonzero command exit
and `scan_completed: false`, rather than appearing as a completed negative
result. Ordinary socket timeout is a separate, passing negative-control case.

## Fresh validation

The complete `--suite all` run exited 0 in **129.057 seconds**. The unchanged
aggregate output is [validation.json](validation.json); the detailed scan CLI
results are [integration.json](integration.json).

| Check | Observed result |
| --- | --- |
| Working NSE socket contracts | 169 passed |
| Forced response replays | 20 passed |
| Isolated ordinary-selection replays | 24 passed |
| Full-index scan CLI, IPv4 | Seven passed |
| Full-index scan CLI, IPv6 | Two passed; IPv6 was available |
| Version scripts selected and loaded during each passing CLI scan | 48 |
| Comparison scans | 28 passed across seven conditions, including 14 warmups |
| Frozen review archive | 1,739 manifest files and retained patch/fixture/contract checks passed |
| Historical evidence | 136 synthetic and 168 Wine/QEMU application scan records rechecked |

The seven IPv4 scenarios use recorded 1.30 and 1.31 responses, the versionless
default Info record, real NetBus 1.70, password denial, a seven-byte truncated
version response, and a silent query timeout. IPv6 repeats the 1.31 positive
and real NetBus negative against `::1`. Every case checks actual XML service
metadata and fixture query traffic. The silent and truncated cases preserve
the existing NetBus identification.

Additional controls passed by observing the expected failures:

- The external absolute-path collision was reproduced against an older
  installed copy from the frozen upstream fixture.
- A temporary action that throws an error was rejected, despite Nmap exit 0.
- A temporary sleeping action was rejected as an NSE timeout, despite Nmap
  exit 0. A retained test shim shortened the script limit to one second; the
  production command uses 20 seconds. The shim's actual command is retained.
- A test executable emitting incomplete XML with exit 0 was rejected.
- Invalid ports and an option-like target were rejected before scanning.
- An existing result directory was not overwritten.
- The installed fixture's old NSE and complete script database retained
  their original hashes.

Expected failure reports in these controls do not indicate failed validation.
Their purpose is to establish that errors cannot be reported as successful
execution. Faulty source copies and shims are evidence only, not the detector.

## Reproduce

From the development branch with the runtime prepared:

```sh
python3 tools/codex-cloud/test.py --suite integration
python3 tools/codex-cloud/test.py --suite all
```

For normal detector use, see the [development guide](../../../docs/codex-cloud-netbus.md).
The command accepts targets, TCP ports, IPv6, an explicit Nmap executable, and
a fresh output directory. Its report contains the raw XML-derived service
attributes. `status: pass` means execution completed successfully; absence of
a NetBuster label does not prove absence of a honeypot.

[results.tar.gz](results.tar.gz) retains all fresh suite commands, logs, XML,
fixture events, reports, fault controls, and tested source files. It includes
the frozen-review aggregate report, but does not duplicate historical raw
application records from the original archive. Verify its files with:

```sh
sha256sum -c SHA256SUMS
tar -xzf results.tar.gz
(cd scan-runner-20261117 && sha256sum -c MANIFEST.sha256)
```

The report's checkout revision is the parent commit before these additions.
`test_runner_sha256` and `scan_runner_sha256` identify the exact tested working
tools. Runtime: Nmap 7.992SVN, Lua 5.4.9, Python 3.12.14. The unchanged engine
was built from `1aa2aaa7ae695bed2f89c2e475f6e003e52b97fb`.

## Evidence limits

All fresh network traffic targeted IPv4 or IPv6 loopback fixture servers.
The normal command uses TCP connect scanning. No new original-application,
native Windows, deployment false-positive-rate, or attacker-deterrence
experiment was performed. Other installed Nmap versions have not been
validated by this run. The retained review snapshot is unchanged.
