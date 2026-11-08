# agent-bot-souls

The Soul runtime for the Soul Agent Platform. It is the entry point
(`agent-bot soul run`) that presents one conversation to the owner, supervises
a Soul's members (a lead and its specialists), routes work by role, and runs
the recovery ladder. Authority stays outside it, in HQ
([agent-bot-daemon](https://github.com/true-line/agent-bot-daemon)).

This repository's charter is its entry in the platform's
[repository catalog](https://github.com/true-line/agent-bot-platform/blob/main/docs/03-architecture/repository-catalog.md).
Its first work is row 14 of agent-bot-daemon's
[migration plan](https://github.com/true-line/agent-bot-daemon/blob/main/docs/daemon-plugin-split.md#9-migration-plan).

Agents start at [AGENTS.md](AGENTS.md).

## License

MIT. See [LICENSE](LICENSE).
