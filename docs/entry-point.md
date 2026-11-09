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
2. **Starts the members.** Each member's adapter runs as its own process, in
   `Contents/home/<member>/`. The entry point drives it over the Agent
   Client Protocol (ACP) on stdio, one turn at a time per member.
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

The entry point passes each member that runtime and its channel binding. In
the cooperative profile the binding is a bearer secret inside the Soul, so a
member that reads another member's binding can speak for it. HQ reports
`managed-cooperative` for that reason. The protected profile (plan row 16)
replaces it with caller-bound handles.

It never approves a permission request from an adapter. It answers
`cancelled`, because approvals are HQ's records of the owner's decisions.

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

It writes `host/members.sock` (0600, in a 0700 directory),
`comms/notes/<note_id>.json` and each member's `home/<member>/`.

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
