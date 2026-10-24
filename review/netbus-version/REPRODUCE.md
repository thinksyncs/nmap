# Reproduce the NetBuster identification fix

This attachment applies the proposed patch to a pinned upstream script and runs
small TCP services on `127.0.0.1`. It needs Python 3.9 or later, Git, and Nmap with
its standard scripts and service database. It does not need root, Wine, the old
applications, or an external target. The system Nmap installation is unchanged.

After extracting `netbus-review.tar.gz`, run from the extracted directory:

```sh
cd netbus-review
python3 run_review.py --output results
```

Use a new output directory for every run. Exit code 0 means all of the following
completed:

- Every bundled file matched the SHA-256 manifest.
- `git apply --check` and actual patch application succeeded; the result exactly
  matched the bundled candidate.
- The candidate identified the recorded positive response and preserved the
  negative result. The review subset also checks split responses, truncated and
  unavailable responses, and a complete signature followed by EOF or an open
  connection. It includes a longer counter with additional response bytes and a
  password-protected `Info;...` response. It exercises both forced NSE execution
  and ordinary `-sV` selection.
- The pinned upstream script falsely identified the timeout and EOF fixtures as
  NetBuster. The runner requires the expected false-identification records and
  successful NSE completion; it does not treat an arbitrary test crash as
  reproduction of the bug.

Some cases deliberately wait for a socket timeout. For all cases in the replay
harness, including malformed signatures, use a fresh output directory:

```sh
python3 run_review.py --full --output results-full
```

To check only attachment integrity and patch application, without opening
sockets:

```sh
python3 run_review.py --verify-only --output results-integrity
```

Results, exact Nmap commands, XML, and logs are written below the chosen output
directory. `review-report.json` distinguishes the expected upstream failure from
candidate regression failures. If the installed Nmap uses a changed service
signature or trace format, inspect the saved logs rather than treating a failed
check as a successful reproduction.

The two JSON fixtures contain application bytes observed from archived NetBuster
1.31 and NetBus 1.70 under the recorded Wine configuration. The request is
`nbver\rGetInfo\r`; the candidate examines the first eight response bytes. The
reduced capture in `controls/recorded-controls.pcap` preserves the selected real
control exchanges. `controls/provenance.json` records the selection, hashes and
runtime. No application executables are included.

Replay changes segmentation, truncation, and timeouts deliberately. Those cases
check the NSE's behavior; they do not measure live application latency or real
world detection rates. Additional measurement reports, when supplied with this
attachment, describe their own live-test environment and scope.

`tests/benchmark_netbus_live.py` is included for reviewers who already have an
isolated environment with one of the actual applications listening on guest
loopback port 12345. The review runner never invokes it. It does not start an
application or create isolation. Unlike replay, it uses a SYN scan and needs
the corresponding packet-capture and raw-socket privileges inside that lab.
With the relevant service already running there, the comparison command is:

```sh
python3 tests/benchmark_netbus_live.py --product netbus \
  --variant upstream=tests/fixtures/upstream/netbus-version.nse \
  --variant nbver-only=evidence/netbus-latency/scripts/nbver-only.nse \
  --variant candidate=nse/netbus-version.nse \
  --repeats 5 --output results-live-netbus
```

Use `--product netbuster` and a fresh output path when the NetBuster application
is running instead. Each variant has a warmup excluded from the summary; the
runner rotates variant order across measurement rounds and saves every timing
sample and Nmap log. This optional live benchmark is separate from the
unprivileged, application-free replay command above.

To apply only the code change to an Nmap checkout, from that checkout run:

```sh
git apply --check /path/to/netbus-review/patches/netbus-version.patch
git apply /path/to/netbus-review/patches/netbus-version.patch
```

The manifest records the exact upstream file used for reproduction. If the
current upstream file differs, review that difference before applying the patch.
