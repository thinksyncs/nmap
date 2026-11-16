# NetBus / NetBuster development

The Cloud workflow is documented in `docs/codex-cloud-netbus.md`.

From the repository root:

```sh
bash tools/codex-cloud/setup.sh
python3 tools/codex-cloud/test.py --suite all
```

For a short edit/test cycle, use `--suite contracts`. Before reporting a NetBus
change as verified, run the relevant replay and comparison suites as well.
The wrapper selects the current `scripts/netbus-version.nse`, including local
edits. Its network tests use loopback fixture servers.

Setup builds the committed Nmap engine in an isolated source copy, with bundled
dependencies and without OpenSSL/libssh2. Commit engine changes before rebuilding;
NSE-only edits do not require rebuilding the engine. Generated binaries, fixtures,
and results live in the ignored `.codex-cache/` directory.

`review/netbus-multiversion/` is a frozen public review snapshot. Preserve its
checksums and evidence. The `review` suite verifies this snapshot, not a modified
working script. Its stored Wine/QEMU measurements are historical application
runs; fresh localhost replays are a separate result.
