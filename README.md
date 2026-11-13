# agent-bot-souls

The Soul runtime for the Soul Agent Platform. It is the entry point that
presents one conversation to the owner, supervises a Soul's members (a lead
and its specialists), routes work by role, and runs the recovery ladder.
Authority stays outside it, in HQ
([agent-bot-hq](https://github.com/true-line/agent-bot-hq)).

This repository's charter is its entry in the platform's
[repository catalog](https://github.com/true-line/agent-bot-platform/blob/main/docs/03-architecture/repository-catalog.md).
The entry point is row 14 of agent-bot-hq's
[migration plan](https://github.com/true-line/agent-bot-hq/blob/main/docs/daemon-plugin-split.md#9-migration-plan).

## Use

```sh
agent-bot-souls run  --soul DIR [--hq-home DIR]   # the ACP front door, on stdio
agent-bot-souls chat --soul DIR [--hq-home DIR]   # a terminal chat with the Soul
```

`DIR` is the Soul package directory, the one that holds `Contents/`.
`--hq-home` is HQ's state directory: `$AGENT_BOT_HQ_HOME`, else
`~/.agent-bot-hq`. HQ must be running with a broker plugin, and the owner
must have accepted the Soul's definition digest there. With the `agent-bot`
shim installed, the same commands are `agent-bot souls run` and
`agent-bot souls chat`
([platform PDR-0037](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0037-agent-bot-executables-are-daemon-plugins-behind-a-shim.md)).

Node 20 or later, no npm dependencies. Unix sockets only, as HQ is today.

Before the first run or test, prepare the pinned contract dependency from
this package's directory:

```sh
npm run prepare:contracts
```

This explicit installation step fetches the public `soul-contracts` release
with credentials disabled, verifies its commit and content digest, and
caches it under `node_modules/.cache/`. An existing valid cache is reused
without network access. Runtime use never fetches. For a read-only install,
prepare the release in a writable deployment directory by setting
`AGENT_BOT_SOUL_CONTRACTS` for that command, and set the same variable when
running the Soul. Every runtime process verifies the dependency before use;
a missing, changed or incomplete release fails with preparation guidance.
The package includes the pin and `scripts/prepare-contracts.mjs`, but no
copied contract schema or fixture.

[docs/entry-point.md](docs/entry-point.md) describes what the entry point
does, the files it reads, what a member can ask of it, and what is not built
yet.

Agents start at [AGENTS.md](AGENTS.md).

## License

MIT. See [LICENSE](LICENSE).
