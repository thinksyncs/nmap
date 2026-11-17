# NetBus / NetBuster development in Codex Cloud

This workflow prepares the repository for repeatable development of
`scripts/netbus-version.nse` in a Codex Cloud workspace. It builds a local Nmap
runtime from committed source and runs the working script against the retained
contract and localhost test cases.

Preparing a checkout and publishing a reusable Codex Cloud environment are
separate steps. This document covers both, while preserving the distinction
between new tests and historical application measurements.

## Source and review baselines

| Material | Reference |
| --- | --- |
| Feature source used for migration | `1aa2aaa7ae695bed2f89c2e475f6e003e52b97fb` |
| Retained review branch snapshot | `0be87f67597ae7275e9e3af427a46169ce7f8e3e` |
| Cloud development branch | `codex/cloud-netbus-dev` |
| Upstream change | [nmap/nmap#3570](https://github.com/nmap/nmap/pull/3570), open at migration preparation |
| Multiversion follow-up | [nmap/nmap#3577](https://github.com/nmap/nmap/pull/3577), draft at migration preparation |

These commit IDs identify the source and retained review material. The Cloud
development branch can acquire later commits. Check the linked pull requests
for their current review state.

## Prepare the runtime

From the repository root, run:

```sh
bash tools/codex-cloud/setup.sh
```

Prerequisites are Linux, Bash, Git, Python 3.9+, GCC/G++, Make, tar, and the
standard `install` and `mktemp` utilities. Setup uses four compiler jobs by
default; `--jobs N` accepts 1 through 16. Use `--rebuild` to discard a successful
runtime cache. The source commit, compiler settings, script, and installation
path determine whether a cached build can be reused.

Setup builds the committed Nmap engine with the repository's bundled libraries
and keeps its local runtime and generated assets under `.codex-cache/`. Once the
checkout and build toolchain are present, the build does not need to download
third-party libraries. Obtaining the repository and provisioning a missing
compiler or other system tools are separate environment setup operations.

The runtime target is **Nmap 7.992SVN with Lua 5.4.9**. The build omits TLS and
SSH-library support. It is intended for these NetBus TCP checks; its results do
not establish that TLS probes or SSH-dependent NSE workflows work in this
configuration. Nmap and its bundled components retain their respective
licenses.

Generated runtime files and test results are local build products. Commit the
source, setup instructions, and relevant review material rather than the
contents of `.codex-cache/`.

## Run the detector

Use the working NSE through the scan command:

```sh
python3 tools/codex-cloud/scan.py -p 12345 192.0.2.10
```

Replace the documentation address with your test target. The command defaults
to TCP port 12345. It also accepts comma-separated ports, ascending ranges,
multiple targets, and `-6` for IPv6. Use `--nmap /path/to/nmap` to select another
installed executable; otherwise it prefers the prepared Cloud runtime and then
`nmap` from `PATH`.

The command performs a TCP connect scan with service detection at intensity 7
and selects `netbus-version` by name. It creates a temporary data overlay with
the working NSE and an unchanged copy of the installed **full** `script.db`.
Other scripts, libraries, and service probes are resolved through Nmap's usual
data lookup. Selection output must confirm the candidate's path and SHA-256.
The existing Nmap installation is left untouched and the overlay is removed
after the process finishes.

This also avoids a concrete external-script loading failure. With an older
installed copy, `nmap -sV --script /another/path/netbus-version.nse` can load
both files and abort with `duplicate script ID: 'netbus-version'`. `-sV`
implicitly selects the version category. A different absolute path does not
replace the installed entry; selecting the overlay copy by name does.

Results are saved in a new directory under `.codex-cache/scans/`, or in the
new directory supplied with `--output`. They include `report.json`, `scan.xml`,
stdout/stderr logs, the exact command, runtime version, source hash, and the
selected version-script inventory. A normal completion has exit code 0;
invalid inputs, incomplete scans, and detector execution failures return
nonzero. Existing result directories are never overwritten.

The report's `status: pass` describes successful execution. Inspect each
service's `product`, `version`, and `extrainfo` for the identification result.
Absence of a NetBuster label is not evidence that a host is not a honeypot.
The supported fingerprints and their limits are those of the working NSE;
this command does not add new product fingerprints.

The initial full-index, IPv4/IPv6, and detector-failure validation is retained
in [`review/codex-cloud/scan-runner-20261117/`](../review/codex-cloud/scan-runner-20261117/README.md).

## Run tests against the working script

Run the complete workflow:

```sh
python3 tools/codex-cloud/test.py --suite all
```

Or select a suite while iterating:

```sh
python3 tools/codex-cloud/test.py --suite contracts
python3 tools/codex-cloud/test.py --suite replay
python3 tools/codex-cloud/test.py --suite ordinary
python3 tools/codex-cloud/test.py --suite integration
python3 tools/codex-cloud/test.py --suite compare
python3 tools/codex-cloud/test.py --suite review
```

Results are written under `.codex-cache/results/`.

| Suite | Purpose | Expected coverage from the retained cases |
| --- | --- | --- |
| `contracts` | Check deterministic behavior using the current working NSE script. | 169 contract cases |
| `replay` | Force the working script to run against localhost response replays. | 20 replay cases |
| `ordinary` | Check normal service-based selection and existing service metadata against localhost replays. | 24 scans: 12 scenarios for each of the 1.30 and 1.31 fixtures |
| `integration` | Exercise the scan CLI with an older installed script and the full NSE index. | Seven IPv4 scans, two IPv6 scans when loopback is available, collision/error controls, and input/output handling |
| `compare` | Run the retained comparison scenarios with the working script as the candidate. | 28 comparison scans |
| `review` | Verify the frozen review archive with its own review harness. | Snapshot contracts, patches, and retained evidence; distinct from working-script validation |
| `all` | Run each suite and retain the resulting records. | The groups above; overlapping snapshot checks are not additional unique live cases |

The counts describe the anticipated case inventory, not a claim that a new
Cloud run has passed. Report the actual exit status and result records from
each run. A changed test inventory should be reflected in the reported counts.

The migration verification is retained in
[`review/codex-cloud/`](../review/codex-cloud/README.md).
The later ordinary-selection gate and full-suite run are recorded in
[`review/codex-cloud/ordinary-selection-20261117/`](../review/codex-cloud/ordinary-selection-20261117/README.md).

The live suites explicitly select the repository's working
`scripts/netbus-version.nse` by path. This matters after an edit: an installed
Nmap copy or a script bundled in an archive must not silently replace the code
under development. The Nmap engine is built from committed source; the live
NSE target is the working file, including uncommitted edits to that file.

### Ordinary service selection

The `ordinary` suite runs `-sV --script netbus-version` without the `+` prefix
that forces a script's port rule to match. The contract harness mocks the port
rule, and forced replays bypass it, so this suite checks a separate integration
boundary: the real Nmap engine must identify the NetBus service and select the
working NSE before the script can classify the response.

Each fixture group includes supported-version and segmented positives, the
versionless default Info fingerprint, real NetBus and password-denied controls,
an unsupported version, malformed response bytes, EOF, timeouts, and altered
or incomplete Info records. Negative cases must retain Nmap's existing service
name, product, and version; simply omitting a honeypot label is insufficient.
There are six expected positive results and 18 negative results across the
24 scans. Shared controls, including the versionless Info cases, run in both
fixture groups; these are not 24 distinct implementations or application runs.

The harness copies the working script into a temporary data directory and
verifies its path and SHA-256 using Nmap's script selection output. It indexes
only `netbus-version` to isolate this script from other version scripts while
retaining the original service probes. This checks service-based selection,
not interactions with the full installed NSE script collection. The wrapper
requires the correct selection mode, candidate implementation, complete case
inventory, source hash, and verified overlay before reporting a pass.

The `integration` suite covers the separate user-facing scan command with the
unfiltered installed script index. It reproduces the absolute-path collision
before testing the overlay, checks complete Nmap XML and service metadata,
and verifies that the installed script and database are unchanged. IPv6
unavailability is reported explicitly rather than silently dropping those
cases. Controlled faulty runners and NSE copies check that failures do not
become successful scan reports.

## Frozen review material and historical measurements

The retained materials are in
[`review/netbus-multiversion/`](../review/netbus-multiversion/README.md). Its
archive is a fixed review snapshot. Running its unchanged harness checks that
snapshot and its retained data; it does not prove that a later edit to
`scripts/netbus-version.nse` is correct. Use the live suites for that question.

The retained evidence includes **136 synthetic scans** and **168 application
scans collected under Wine/QEMU**. Rechecking their stored records is a
historical-data validation step. It is not a new run of the original
applications and should not be presented as one.

No Windows application executables or virtual-machine disks are included in
the bundle. Reproducing the original application experiments would require a
separately prepared application environment and the relevant samples. Native
Windows behavior and real-world detection rates are outside the evidence
established by the retained records and localhost replays.

## Register a reusable Codex Cloud environment

Use the environment creation flow to make this setup available to future
tasks. The official [Cloud environments documentation](https://learn.chatgpt.com/docs/environments/cloud-environments)
describes creation, review, saving, and publication.

1. Open **Settings > Codex Cloud > Environments > Create environment**.
2. Select the repository containing `codex/cloud-netbus-dev`. Check out that
   branch for the setup task.
3. In the setup task, run `bash tools/codex-cloud/setup.sh`, then
   `python3 tools/codex-cloud/test.py --suite all`.
4. Review the configuration, setup results, and generated test records. Resolve
   any failed or unfinished setup work and save the configuration.
5. Select **Publish**. After publication completes, select the published
   environment when starting a new task.

An ordinary Cloud task can prepare and test this repository without being an
environment-creation session. This migration workspace does not expose an
environment-management API, so preparing these files does not by itself
register or publish a reusable environment. Complete the registration flow
above to make the prepared setup selectable for later tasks.

## Migration scope

The deliverable is a reproducible source-based development workflow. It does
not establish the identity or contents of a previous GCP VM, and it does not
represent a disk-image transfer from that VM. The source GCP VM remains
unidentified, so VM-specific files, configuration, and uncommitted work cannot
be claimed as transferred.

For a migration result, record the checked-out revision, runtime versions,
executed suites and their actual outcomes, and whether reusable-environment
publication has completed. Keep those statements separate from historical
review results and upstream pull-request status.
