# The entry point

`agent-bot-souls` is the process that runs a Soul on a host. This page says
what it does, what it reads, and what it leaves to others. The design it
follows is the platform's
[lifecycle](https://github.com/true-line/agent-bot-platform/blob/main/docs/03-architecture/lifecycle.md)
and sections 3, 5, 7 and 9 of the
[0.4 draft](https://github.com/true-line/agent-bot-platform/blob/main/docs/papers/soul-platform-draft-0.4.md).

## What it does

1. **Clocks in.** It sends `Hello` to HQ on `admission.sock`, then `Equip`
   for each admitted runtime, `Ready` when a member is up, and `Lease`
   renewals. HQ decides admission, the profile in force, the installation
   epoch and the lease generation.
2. **Starts the members.** The entry point first asks HQ to launch each
   adapter in its harness account and drives the attached stream over the
   Agent Client Protocol (ACP), one turn at a time per member. In the
   cooperative profile only, an explicit `host.launch_unavailable` refusal
   falls back to a local process in `Contents/home/<member>/`.
3. **Gives the owner one conversation.** A prompt at the front door is one
   turn of the lead. The lead's reply is streamed back.
4. **Routes by role.** The lead asks the entry point to hand a prompt to
   the member with a role, and gets that member's reply when its turn ends.
5. **Keeps typed notes.** A member writes notes through the entry point,
   which stamps who wrote them and when. A lead that starts or takes over
   is given the live handoff notes before its first turn.
6. **Runs the recovery ladder** when a member fails.

## What it never does

It holds no keys and decides no grant. It does not commit to tasks. A member
commits for itself: it binds its own connection to HQ's `broker.sock` with
the runtime HQ admitted it as, and HQ checks every request.

The entry point passes each member that runtime and its channel binding. The
member never sends the binding to the broker. It asks HQ for a challenge and
answers with a proof keyed by the binding (plan row 16a). If HQ offers no
challenge the member can answer, the bind fails; nothing falls back to
sending the binding.

In the cooperative profile the binding is still a bearer secret inside the
Soul, so a member that reads another member's binding can speak for it. HQ
reports `managed-cooperative` for that reason. Where the owner configures a
harness account, HQ launches the adapter there, gives it that account's own
broker endpoint, and accepts the runtime from that endpoint alone (plan row
16b). HQ's returned account-private directory is the ACP session directory.
The entry point supplies only the member token; HQ derives the member ID,
role and both socket paths from the admitted runtime and verified account.
Adapter-defined environment variables are refused instead of silently dropped.

For the current pilot, HQ and the Soul entry point share the host UID, so the
entry point can bind the returned path inside HQ's harness endpoint directory.
The later dedicated-HQ-account move must replace that transitional ownership
with an HQ-owned proxy or a separately provisioned entry-point directory. This
integration does not claim that service-account boundary is complete.

`--profile managed-protected` requests protected operation and fails before
an adapter starts if HQ grants a weaker profile or account launch cannot be
used. Omitting `--profile` selects the default. Supplying it without a value stops startup before HQ admission.
The default `managed-cooperative` request preserves existing hosts: it
uses local spawn only when HQ explicitly reports `host.launch_unavailable`.
Before request-time fallback it proves the admitted runtime may use HQ's
shared broker; an account-bound runtime with no returned endpoint fails
closed. If attach fails after a reservation returned its verified endpoint,
fallback uses that account endpoint.

It never approves a permission request from an adapter. It answers
`cancelled`, because approvals are HQ's records of the owner's decisions.

On the ACP front door, `session/cancel` applies to the named session's
oldest unfinished prompt. A queued prompt is removed and completes as
`cancelled` while the active turn continues. For a running prompt the entry
point forwards the notification and waits for the adapter's result. An ACP
request-cancelled error confirms cancellation. Other errors and uncertain
outcomes from earlier attempts can still reach the client. Cancellation
prevents further automatic prompt retries.

## Files it reads

Everything is under `<package>/Contents/`
([soul-package layout](https://github.com/true-line/soul-package/blob/main/spec/LAYOUT.md)).

| File | Fields read |
| --- | --- |
| `SoulInfo.json` | `soul_id`; `members[]` with `member_id`, `role`, `adapter_id`, `adapter_version` and an optional `fallbacks[]` of `adapter_id` and `adapter_version` |
| `SoulLock.json` | `definition_digest` |
| `host/adapters.json` | per adapter ID: `command` (an argument list), optional `env`, optional `accepts` (data-restriction labels the route may receive) |
| `host/installation.json` | `installation_id`. Created on first start. |

Exactly one member has the role `lead`. soul-package does not yet specify
the fields of `SoulInfo.json` or `SoulLock.json`; the entry point reads only
these and ignores the rest.

It writes `host/members.sock` (0600, in a 0700 directory) for cooperative
local fallback. An HQ launch gets a per-launch 0660 member socket in the
harness account's verified endpoint directory; the entry point bounds
unauthenticated connections, requires the member token within five seconds,
and removes the socket on stop. It also writes `comms/notes/<note_id>.json`
and, for local fallback, each member's `home/<member>/`.

## What a member can ask

The entry point starts a member with `AGENT_BOT_SOULS_SOCKET` and
`AGENT_BOT_SOULS_MEMBER_TOKEN`. An adapter written in JavaScript imports
`lib/member.mjs`. A harness that only runs commands uses
`agent-bot-souls member <op> [JSON]`.

| Operation | Goes to | What it does |
| --- | --- | --- |
| `runtime` | entry point | The member's current runtime, epoch and lease generation |
| `directives` | HQ broker | The Soul's waiting directives |
| `get` | HQ broker | One of the Soul's tasks, with its proposals |
| `commit` | HQ broker | A task/v1 commitment. From a specialist HQ records it as a proposal. |
| `route` | entry point | Lead only: a turn of the member with a role |
| `note` | entry point | Write a typed note |
| `handoffs` | entry point | The live handoff notes |

A commitment whose reply was lost is reconciled, never replayed under a new
operation ID. The same request is sent again while the runtime is the same,
which returns HQ's stored receipt. After a new admission the task record is
read back, and it says whether the commitment landed.

## Bound member queries

`connectMember(env).queries` is the supported SDK capability for plugin
queries over the member's existing authenticated broker connection:

```js
await member.queries.request('notices.peek', (freshness) => ({
  // Build the operation's validated shared record here.
  ...freshness,
}), { replay: 'read-once' });
```

The builder must be synchronous. It receives a frozen copy of exactly
`installation_epoch` and `lease_generation` for the concrete connection that
will send its result. It receives no runtime record, channel binding, token,
remote harness or repository policy. The operation's own client still
validates its released shared query/result contract; the generic port does
not replace that boundary.

The SDK's replay policy and driver contract live in
[HQ's member-query port](https://github.com/true-line/agent-bot-hq/blob/f3c39d2a703085c14bc09f8f0042d048f30525dc/docs/hq-member-query-port.md).
The default is `never`. Only the fixed read kinds `task.get`,
`task.directives` and `notices.peek` can use `read-once`. Recovery captures
one replacement binding and rebuilds the payload once from its freshness.
Consume-one, task commitments and unknown kinds never gain replay through
that option. Existing `member.commit()` keeps its separate operation-ID
reconciliation behavior.

The Soul runtime adapts its existing member bootstrap environment to the
[shared SDK member session](https://github.com/true-line/agent-bot-hq/blob/69505d72ba30dd6c8129397baadb3b0b3397fbbd/docs/hq-member-bootstrap-client.md).
That is the single implementation of local socket framing, challenge/HMAC,
capture/reconnect and session cleanup. `lib/hq-client.mjs` retains only the
runtime's verified-contract default, `lib/ndjson.mjs` re-exports the shared
line codec, and `lib/member.mjs` keeps the Soul-specific task workflow.

Concurrent captures share one completed binding. Freshness recovery accepts
only validated shared refusals or a transport failure; it cannot tear down a
newer pair. Consume-one is never replayed, and a later explicit capture may
repair a stale pair. Malformed member hello closes its entry connection before
runtime lookup. Contract callbacks must validate synchronously; a returned
promise refuses before sending or accepting a record.

Existing `member.commit()` uses the private SDK owner facade's
`runtimeFor`/`requestOnce` so its operation-ID reconciliation remains separate
from generic query invalidation. Public `runtime()` still returns a fresh,
redacted metadata object. Token issuance, renewal and replacement remain with
the same runtime owner, and authority checks remain at HQ.

The exact SDK client/session/codec files are pinned to the reviewed HQ commit
in `governance/pins.json`, with per-file hashes and the license in
`lib/vendor/agent-bot-sdk/source.json`. This follows existing commit-based SDK
provenance; the shared contract release remains independently verified.

This provider does not register a notice consumer, publish a new notice schema,
start an MCP server or activate a queue. Actual identity MCP composition is
still [HQ #131](https://github.com/true-line/agent-bot-hq/issues/131), and legacy
notice acceptance remains [HQ #13](https://github.com/true-line/agent-bot-hq/issues/13).
The transport tests use real pinned HQ admission/broker/storage plus a test-only
query handler and a local connection-fault proxy; they do not claim released
notice-consumer or MCP integration evidence.

## Contract validation

The runtime consumes `soul-contracts` v0.5.0 through the commit and
`sha256-manifest-v1` digest in `governance/soul-contracts.json`. The explicit
preparation step is documented in the [README](../README.md). Schemas and
fixtures stay in that external dependency; none is copied into this
repository. The SDK client, session, parsing, schema and canonicalization modules in
`lib/vendor/agent-bot-sdk/` carry their source commit, byte hashes and MIT
notice. Tests compare their bytes with the same HQ revision the runtime's
integration tests use.

The production clients validate outgoing Hello, Ready/Lease and task
commitments, incoming admission, Equip, task records, directives and typed
refusals. Admission replies must echo the Hello request and select versions
the runtime both implements and offered. HQ and member sockets reject
duplicate JSON keys, malformed envelopes and replies with no pending request.
Notes are checked against the pinned typed-note schema before writing and
after reading. A corrupt or unreadable stored note makes its handoff
restrictions unavailable; it is never silently discarded to allow fail-over.

`tests/contracts.test.mjs` runs every shared positive and negative fixture
through the runtime codec for its schema/parse verdict (38 positives and 88
negatives across 19 schemas), checks their byte pins and canonicalization
vectors, and exercises the two T14 version/capability refusals. This is
component evidence for the platform's
[Stage 0 gate](https://github.com/true-line/agent-bot-platform/blob/main/docs/10-program/roadmap.md),
not a `soul-conformance` result. The schema-valid stale epoch, unaccepted
definition, insufficient profile and expired approval/frame fixtures still
need authority or time context: their semantic errors remain HQ's or the
broker's responsibility. They are not reported as runtime authorization
checks. Likewise, the local request/reply envelope and Ready/Lease reply
remain HQ framing until soul-contracts specifies them (soul-contracts #34).

## The recovery ladder

The entry point classifies a failure before it acts.

| Failure | How it is recognised | What happens |
| --- | --- | --- |
| Crash | The member process exits | Restart after 5 s, 30 s, 2 min, then 10 min. The fifth crash in an hour quarantines the Soul until the owner releases it. |
| Authentication | ACP error -32000 | HQ re-equips the member and the turn is tried again. A second failure in a row is the owner's decision. |
| Provider outage | Error data `failure: provider_unavailable` | Fail over to the member's next route. A route is used only if it accepts every restriction label on the live handoff notes; otherwise the work pauses. |
| Identity-service outage | Error data `failure: credential_unavailable` | Wait. No restart and no fail-over. |
| Unknown outcome | A lost reply to a commitment | Reconcile, as above |

A restarted member is a new runtime, so a restart or a fail-over is a new
admission. The new lease generation fences the old lead. Members that kept
running move to their new runtime the next time HQ refuses the old one.

How an adapter names a provider outage or a missing credential is this
repository's reading until the `harness-adapter` contract in soul-adapters
specifies it.

## The fake adapter

`agent-bot-souls fake-adapter` is an ACP agent with scripted behaviour and
no model. As the lead it accepts each waiting directive, runs it, routes it
to the specialist, and makes the final commitment from the proposal. As a
specialist it produces an artifact and proposes. It exists so the entry
point can be run and tested before a real adapter does. Real adapters come
from [soul-adapters](https://github.com/true-line/soul-adapters).

## Not built yet

- `Brief` as an HQ operation. soul-contracts has no schema for it, so the
  entry point builds the brief itself from the handoff notes, and the lead
  reads its directives from HQ.
- Interactive turns preempting background work. A member takes one turn at
  a time, in order.
- Checking a fail-over route against task records. The check uses the
  restriction labels the lead put on its handoff notes.
- The Soul runtime's HQ side as a plugin (validation, render, candidate
  promotion), dream runs, and the mirror of task records in `comms/`.
- Windows. HQ's sockets are Unix sockets today.
