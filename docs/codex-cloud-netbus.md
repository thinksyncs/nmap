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

## Run tests against the working script

Run the complete workflow:

```sh
python3 tools/codex-cloud/test.py --suite all
```

Or select a suite while iterating:

```sh
python3 tools/codex-cloud/test.py --suite contracts
python3 tools/codex-cloud/test.py --suite replay
python3 tools/codex-cloud/test.py --suite compare
python3 tools/codex-cloud/test.py --suite review
```

Results are written under `.codex-cache/results/`.

| Suite | Purpose | Expected coverage from the retained cases |
| --- | --- | --- |
| `contracts` | Check deterministic behavior using the current working NSE script. | 169 contract cases |
| `replay` | Exercise the working script against localhost response replays. | 20 replay cases |
| `compare` | Run the retained comparison scenarios with the working script as the candidate. | 28 comparison scans |
| `review` | Verify the frozen review archive with its own review harness. | Snapshot contracts, patches, and retained evidence; distinct from working-script validation |
| `all` | Run each suite and retain the resulting records. | The groups above; overlapping snapshot checks are not additional unique live cases |

The counts describe the anticipated case inventory, not a claim that a new
Cloud run has passed. Report the actual exit status and result records from
each run. A changed test inventory should be reflected in the reported counts.

The migration verification is retained in
[`review/codex-cloud/`](../review/codex-cloud/README.md).

The live suites explicitly select the repository's working
`scripts/netbus-version.nse` by path. This matters after an edit: an installed
Nmap copy or a script bundled in an archive must not silently replace the code
under development. The Nmap engine is built from committed source; the live
NSE target is the working file, including uncommitted edits to that file.

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
