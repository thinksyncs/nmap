# NetBuster identification: review evidence

The proposed change replaces `netbus-version.nse`'s identification from a failed
authentication read with the explicit NetBuster 1.31 version response. It sends
`nbver\rGetInfo\r` and requires a successful read of the eight-byte signature.
The second query avoids waiting for a timeout on default NetBus 1.70.

## Reproduce without the old applications

Download [netbus-review.tar.gz](netbus-review.tar.gz), verify it against
[SHA256SUMS](SHA256SUMS), and run:

```sh
tar -xzf netbus-review.tar.gz
cd netbus-review
python3 run_review.py --output results
```

This needs Python 3.9+, Git, and Nmap with its standard data. It uses localhost
only and does not need root or Wine. The default run verifies hashes and patch
application, checks 13 candidate cases, and reproduces two upstream false
identifications. `--full` runs 31 forced and ten ordinary-selection candidate
cases plus the same upstream cases. The extracted archive passed that full run
before submission; see [pre-submit-verification.json](pre-submit-verification.json).

[REPRODUCE.md](REPRODUCE.md) describes the checks and optional live benchmark.
The archive is the frozen review snapshot; its embedded PR draft predates
submission. No application executables are included.

The separate [socket contract module](netbus_candidate_contract.lua) provides
the 41 mock-socket cases. Save it next to the archive, then from the extracted
`netbus-review` directory run:

```sh
mkdir -p tests/nselib
cp ../netbus_candidate_contract.lua tests/nselib/
nmap --unprivileged -n --datadir tests --script unittest \
  --script-args "unittest.run,unittest.tests={netbus_candidate_contract},classifier.root=\"$PWD\"" -d1
```

Require both `41 of 41 tests passed` and `All tests passed`; Nmap's exit code
alone does not establish test success. This standalone invocation also passed
before submission; see [unit-verification.json](unit-verification.json).

## Measured results

The actual archived applications ran under Wine 10.7 / Alpine 3.22.7 in one
isolated QEMU 11.1.1 VM. Nmap 7.97 used `-sS -sV`. Each variant had one excluded
warmup and five measured runs, with order rotated between rounds. All runs
checked the expected product and version.

| Median duration | Upstream | `nbver` only | Proposed change |
| --- | ---: | ---: | ---: |
| NetBus 1.70, NSE phase | 0.06 s | 5.07 s | 0.06 s |
| NetBuster 1.31, NSE phase | 5.32 s | 0.38 s | 0.40 s |
| NetBus 1.70, whole process | 2.603096 s | 7.708108 s | 2.617980 s |
| NetBuster 1.31, whole process | 8.188152 s | 2.977965 s | 2.986457 s |

[latency-results.json](latency-results.json) records all summaries. The archive's
`evidence/netbus-latency/live/` contains raw samples, commands, XML, logs, source
snapshots, and the full capture. No outliers were removed. The largest proposed
NetBuster whole-process duration was 4.543883 s. NSE phase durations have 0.01 s
resolution; small differences do not establish performance superiority.

## Controls and scope

[recorded-controls.pcap](recorded-controls.pcap) preserves six complete TCP
streams, byte-for-byte from the full capture: a coalesced and a split query for
NetBuster, default NetBus, and password-protected NetBus. [Provenance](controls-provenance.json)
records the source archives, executable hashes, settings, and frame selection.
Paths to the full capture and raw results in the JSON refer to the extracted
archive. Eighteen direct controls were checked in total. Protected NetBus also
retained its product/version in two scans per upstream/proposed variant,
including one warmup.

These controls establish observed behavior in this Wine setup. Positive coverage
is NetBuster 1.31 with the recorded default configuration. Native Windows, other
versions, and other NetBuster settings remain unverified. NetBus used disabled
Wine audio/MIDI drivers. NetBuster crashed in an earlier TCP-connect-scan test,
so the successful live measurements use SYN scanning. Archive hashes identify
the obtained bytes; they do not authenticate the original authors. No deployment
false-positive rate or detection rate is claimed.
