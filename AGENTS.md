# AGENTS.md

agent-bot-souls is the Soul runtime for the Soul Agent Platform: the entry
point (`agent-bot soul run`) that supervises a Soul's members inside the Soul
and runs the recovery ladder. It is untrusted for authority: keys and grant
decisions belong to HQ (agent-bot-daemon). Harness instruction files live in
the user directory, not in this repository (ENG-0384).

<!-- platform:agent-bot-platform:start -->
Platform: true-line/agent-bot-platform, read at main.
This repository's charter, seams and requirements are in the platform's
registry/repos.yaml entry for agent-bot-souls. Read the platform's AGENTS.md
at the start of every task, and before changing a seam or anything a
requirement covers.
<!-- platform:agent-bot-platform:end -->

<!-- governed:shared-agent-discovery:start -->
Shared agent conventions, skills, SOPs and org-wide decisions are discovered from [qwts/qwts-agent-sop](https://github.com/qwts/qwts-agent-sop): start at the [agent conventions](https://github.com/qwts/qwts-agent-sop/blob/main/docs/reference/agent-conventions.md), then the [SOP index](https://github.com/qwts/qwts-agent-sop/blob/main/docs/sop/README.md) and the [ENG decisions index](https://github.com/qwts/qwts-agent-sop/blob/main/docs/decisions/README.md). Inherit by default and vary by explicit delta (ENG-0008). Resolve the current approved SOP head once per operation and record the commit you read.
<!-- governed:shared-agent-discovery:end -->

## Where things live

| What | Where |
| --- | --- |
| Requirements, tests, architecture, trust domains, repository charters, seams, cross-repository decisions, glossary | The platform, read at `main`. Link to it; never copy it here. |
| Schemas, fixtures and error codes | true-line/soul-contracts, pinned by commit. No copies here. |
| The migration steps this repository carries | agent-bot-daemon's [plan, section 9](https://github.com/true-line/agent-bot-daemon/blob/main/docs/daemon-plugin-split.md#9-migration-plan) (row 14, the entry point) |

## Rules

- **The platform wins.** Where this repository disagrees with the platform, follow the platform and record the conflict in its drift register.
- **No authority here.** No signing keys, no grant decisions, no credentials at rest. The runtime asks HQ over `hq/v1` and the broker; it never decides for itself.
- **No schema edits to make code pass.** A contract change goes through soul-contracts first.
- **No personal names.** Write "the owner" or "True Line AI LLC".

## Validate before push

```sh
npm test
```

Node 20 or later, no dependencies.
