# Souls runtime release candidate and qualification input

The build starts with a content-addressed npm `.tgz` and derives a selected
Machine-compatible USTAR tar for the macOS R component. The tar contains the
same bytes for 40 of the 44 npm files. It omits only `README.md`,
`scripts/prepare-contracts.mjs`, `lib/vendor/agent-bot-sdk/source.json`, and
the Linux-only `lib/helpers/member-peer.py`. The signed subject is the exact
selected tar; the signed predicate binds its npm source digest, selection
manifest, omissions, builder, source commit and workflow. Node, Contracts, and
the adapter remain separately pinned Machine components. This runtime is
distinct from an editable `.soul` payload. A successful
build workflow produces a **private candidate**, not a certified release or a
passing physical gate.

## Protected build

1. Review an exact commit on protected `main`. Dispatch
   `souls-build-receipt.yml` with that commit as `approved_source_commit`, plus
   the SHA-256 and UTC observation time of the owner's fresh private R2 lock
   attestation. The workflow refuses a different SHA or unprotected ref. It
   also refuses to build until Souls adopts the exact Contracts release pin
   required by that workflow and the matching reviewed HQ SDK pin.
2. Approve the `qualification-release` environment for this exact run. The
   workflow tests the checked-out source, builds the npm archive, selected R tar and in-toto
   Statement, proves live R2 canary lock enforcement, uploads each asset once,
   reads each back through separate reader credentials, signs the Statement
   using Actions OIDC, and checks its identity and public log inclusion.
3. Preserve the job summary's `souls-private-r2-handoff-v2` JSON as
   `private-handoff.json`. It names all three exact SHA-256 digests, byte lengths,
   private object locators, source commit and tree, workflow, run ID, and
   attempt. It also preserves the exact nonsecret build-inputs and toolchain
   inventories with their file-byte digests, so the offline reviewer can
   inspect the builder/toolchain selectors. The workflow writes the same JSON
   to its build directory.

The live canary proves current overwrite/delete refusal. It does not prove the
lock duration. The owner must review the 365-day rule in the private dashboard
before dispatch and again after upload; preserve the two attestations outside
CI. A stale or missing attestation causes private transport to refuse work.

## Independent private readback and offline check

Use a separate approved reader with fresh owner lock attestation to call
`scripts/r2-private-assets.py read` for all three handoff URIs. Supply the handoff's
digest and byte length, and put each object in a new file named
`sha256-<digest>.tgz`, `sha256-<digest>.tar`, or
`sha256-<digest>.sigstore.json`. Preserve the readback
receipts. Transfer these exact files, the handoff JSON, an owner-approved
Sigstore TrustedRoot JSON, and an approved Cosign binary to a network-isolated
verification host. Record and independently approve SHA-256 pins for the root
and binary. The verifier does not itself prove network isolation.

Run `scripts/verify-souls-build-candidate.py` with `--archive`, `--selected-tar`, `--bundle`,
`--handoff`, `--trusted-root`, `--cosign`, and `--out`; supply the approved
`--trusted-root-sha256`, `--cosign-sha256`, `--source-commit`, `--source-tree`,
`--builder-sha256`, `--derivative-builder-sha256`, and `--toolchain-sha256`. The digest arguments use
`sha256:<64 lowercase hex>`; commit and tree use 40 lowercase hex. The check
rebuilds the selected tar from the npm archive byte for byte and binds both
archives to the handoff, signed in-toto subject, source/build
selectors, exact Actions workflow identity and SHA, and owner-pinned local
trust material. It calls `cosign verify-blob-attestation` with
`--check-claims=true` over the selected tar. Any failed check refuses an output
record. Synthetic unit tests only verify this wrapper's refusal behavior;
they are not cryptographic evidence.

The verification output deliberately records `release_certified:false` and
`physical_qualification:false`. Owner release review must join the post-upload
lock attestation, readback receipts, approved signing material and root pins,
public log proof, offline verification outcome, and selected source/digest into
one release decision. Machine A and the designated physical host must then
bind the chosen runtime digest into the signed install plan and independently
prove T01–T03 and T21. No CI run or source fixture substitutes for that proof.

For a brokered-B T21 candidate, preserve the A-signed primary and private B
assignment, the exact owner-reviewed install receipt, and the ordering record:
A stages the primary without exposing the watched R request; HQ verifies the
live B HMAC bind and relay peer/inode; A then publishes that R request once.
If B bind or relay verification fails, R remains unpublished. The current
Souls B preflight refuses attach and stock member launch until the corresponding
HQ reply and Machine producer exist. The signed selected tar receipt proves
runtime provenance, not this B-before-R ordering or physical T21.
The A-signed order to publish R is only intent. Machine must persist a separate
A-signed publish outcome on the exact watched request inode after the rename and
sync, and its dispatcher must pass that outcome to R only after a bounded
same-inode read. R independently verifies the outcome against its canonical
request, reservation, host launch identity and expiry before H attach; a
missing or changed outcome closes the B start. The exact B FD3 projection and
outcome schema remain a cross-lane release dependency. The B projection is
`cooperative-start/v2`: it carries R-visible member and relay paths, the
signed outcome, and the dispatcher-observed request identity. The disk request
is the common `/v1` object. Its B mode is A-owned, runner-group `0640`; direct
mode retains `0440`. The installed plan must authorize that exact B mode.
Machine's open-FD wait supplies the identity; R does not reopen the path.
The current B ingress target is the measured local deterministic test provider;
its fixture result does not establish general vendor internet forwarding.
