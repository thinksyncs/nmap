# Defensive honeypot camouflage development

## Project objective

The main deliverable is server-side code that makes a legitimate service imitate
honeypot behavior, so an independent detector labels that service as a honeypot
while its real application functions continue to work. The hoped-for outcome is
that attackers avoid it; a detector label alone does not demonstrate deterrence.

The current priorities and acceptance criteria are in
`docs/honeypot-camouflage-roadmap.md`. Continue from the recovered Dionaea HTTP
camouflage baseline in `review/honeypot-signals-v0.1.0/`, not from an assumption
that this project only develops honeypot detectors.

- Treat detector research, NSE code, and NetBus tests as evaluation assets.
  Detector feature expansion is not the main product backlog.
- Evaluate the same legitimate service on the same port with camouflage off,
  the adapter in pass-through mode, and camouflage on. Keep the detector and
  probe database fixed. Do not modify the detector to manufacture success.
- Preserve valid application behavior, including authentication, writes,
  sessions, errors, and HTTP OPTIONS/CORS where applicable. An extra decoy port
  or a response-only fixture does not establish this property.
- Count a complete, positive detector classification separately from detector
  errors, timeouts, or missing results. Record negative and incompatible outcomes.
- Separate historical evidence, fresh localhost measurements, compatibility
  claims, and attacker-behavior evidence.
- Keep the original recovered ZIP and `review/netbus-multiversion/` immutable.
  Make new implementations and measurements outside these frozen snapshots.

## HTTP camouflage baseline

After preparing the runtime below, reproduce the original fixture with a paired
off/on/off comparison using the unchanged service-probe database:

```sh
python3 tools/codex-cloud/test_camouflage.py
```

This is a localhost reproduction of a small HTTP application. Its report must
retain the known OPTIONS compatibility failure; it is not a production-adapter
acceptance test. See the roadmap for the next Lua profile and application gates.

## Retained NetBus / NetBuster evaluation workflow

The Cloud workflow is documented in `docs/codex-cloud-netbus.md`.

From the repository root:

```sh
bash tools/codex-cloud/setup.sh
python3 tools/codex-cloud/test.py --suite all
```

For a short edit/test cycle, use `--suite contracts`. Before reporting a NetBus
change as verified, run the relevant replay and comparison suites as well.
Use `--suite ordinary` to check real service-based script selection and
preservation of existing NetBus metadata; `--suite all` includes this gate.
Use `--suite integration` after changing `tools/codex-cloud/scan.py`; it checks
the user-facing runner with the full script index and an older installed NSE.
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
