// A fake harness adapter: an ACP agent with scripted behaviour and no
// model. It lets the entry point be run and tested end to end before any
// real adapter exists (plan §9 row 14: "lead plus specialist on fake
// adapters"). Real adapters come from soul-adapters.
//
// As the lead, a turn works every waiting directive and every open task a
// handoff note names: accept, run, hand the work to the specialist by role,
// then make the one final commitment from the specialist's proposal. Each
// step reads the task record first and uses an operation ID fixed by the
// task and the step, so a lead that takes over after a crash continues
// from the record and repeats nothing.
//
// As a specialist, a turn produces an artifact for the task it was routed
// and sends `completed`, which HQ records as a proposal.
//
// FAKE_ADAPTER_SCENARIO is JSON for the recovery tests:
//   { "crash": "on-start" | "on-prompt" | "before-final", "once": true }
//   { "fail": "auth" | "provider" | "credential", "once": true }
//   { "probe": true }   a specialist tries what only a lead may do and
//                        writes the refusal codes to probe.json
// `once` applies it the first time only, across restarts.
import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { rpcPeer, RpcError } from './jsonrpc.mjs';
import { connectMember } from './member.mjs';

const ACTIVE = ['accepted', 'running', 'waiting', 'reconciling'];
const FAILS = {
  auth: () => new RpcError(-32000, 'Authentication required'),
  provider: () => new RpcError(-32603, 'provider unavailable', { failure: 'provider_unavailable' }),
  credential: () => new RpcError(-32603, 'credential unavailable', { failure: 'credential_unavailable' }),
};

export function runFakeAdapter({ input = process.stdin, output = process.stdout, env = process.env } = {}) {
  const scenario = env.FAKE_ADAPTER_SCENARIO ? JSON.parse(env.FAKE_ADAPTER_SCENARIO) : {};
  const role = env.AGENT_BOT_SOULS_ROLE;
  const MARK = '.fake-adapter-once';
  // Should the scenario apply now? With `once`, only the first time.
  const applies = () => {
    if (!scenario.once) return true;
    if (existsSync(MARK)) return false;
    writeFileSync(MARK, '');
    return true;
  };
  const crashAt = (point) => { if (scenario.crash === point && applies()) process.exit(70); };
  crashAt('on-start');

  let sessionId;
  const peer = rpcPeer({
    input,
    output,
    onClose: () => process.exit(0),
    methods: {
      initialize: async () => ({ protocolVersion: 1, agentCapabilities: {}, authMethods: [] }),
      'session/new': async () => { sessionId = `sess_${randomBytes(6).toString('hex')}`; return { sessionId }; },
      'session/cancel': async () => {},
      'session/prompt': async (params) => {
        crashAt('on-prompt');
        if (scenario.fail && applies()) throw FAILS[scenario.fail]();
        const say = (text) => peer.notify('session/update', { sessionId, update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text } } });
        const member = await connectMember(env);
        try {
          if (role === 'lead') await leadTurn(member, say, crashAt);
          else await specialistTurn(member, say, params.prompt.map((b) => b.text).join('\n'), scenario);
        } finally {
          await member.close();
        }
        return { stopReason: 'end_turn' };
      },
    },
  });
}

async function leadTurn(member, say, crashAt) {
  const notes = await member.handoffs();
  const ids = new Set();
  for (const d of await member.directives()) {
    const task = d.payload.task;
    await member.commit({ task_id: task.task_id, expected_revision: task.revision, operation_id: `accept:${task.task_id}`, transition: 'accepted' });
    ids.add(task.task_id);
  }
  for (const n of notes) if (n.task_id) ids.add(n.task_id);
  let worked = 0;
  for (const taskId of ids) {
    let { task, proposals } = await member.get(taskId);
    if (!ACTIVE.includes(task.status)) continue;
    worked += 1;
    if (task.status === 'accepted') {
      await member.commit({ task_id: taskId, expected_revision: task.revision, operation_id: `run:${taskId}`, transition: 'running' });
      ({ task, proposals } = await member.get(taskId));
    }
    let proposal = proposals.find((p) => p.role === 'specialist' && p.transition === 'completed');
    if (!proposal) {
      await member.note({
        type: 'handoff',
        task_id: taskId,
        body: `Task ${taskId} is running. The specialist was asked for a proposal. Complete the task from that proposal; ask again only if the task has none.`,
        ...(task.restrictions?.labels?.length ? { disclosure_restrictions: task.restrictions.labels } : {}),
        superseded_note_references: notes.filter((n) => n.task_id === taskId).map((n) => n.note_id),
      });
      await member.route('specialist', JSON.stringify({ task_id: taskId, objective: task.objective, done_criteria: task.done_criteria }), { task_id: taskId });
      ({ task, proposals } = await member.get(taskId));
      proposal = proposals.find((p) => p.role === 'specialist' && p.transition === 'completed');
    }
    if (!proposal) { say(`Task ${taskId} has no proposal yet.\n`); continue; }
    crashAt('before-final');
    const receipt = await member.commit({
      task_id: taskId,
      expected_revision: task.revision,
      operation_id: `complete:${taskId}`,
      transition: 'completed',
      result_ref: proposal.evidence[0],
      evidence_refs: [proposal.proposal_id],
    });
    const live = (await member.handoffs()).filter((n) => n.task_id === taskId).map((n) => n.note_id);
    await member.note({ type: 'commitment', task_id: taskId, body: `Completed ${taskId} at revision ${receipt.revision} from proposal ${proposal.proposal_id}.`, sources: [proposal.proposal_id], superseded_note_references: live });
    say(`Completed ${taskId} from ${proposal.member_id}'s proposal ${proposal.proposal_id}.\n`);
  }
  if (worked === 0) say('No waiting directives and no open tasks.\n');
}

// What a specialist may not do, tried, with the code each attempt got.
async function probe(member, taskId) {
  const tries = {
    route: () => member.route('lead', 'do my work'),
    note: () => member.note({ type: 'rumour', body: 'x' }),
    route_peer: () => member.route('specialist', 'x'),
  };
  const codes = {};
  for (const [name, fn] of Object.entries(tries)) {
    try { await fn(); codes[name] = 'ok'; } catch (e) { codes[name] = e.code; }
  }
  codes.note_id = (await member.note({ type: 'finding', task_id: taskId, body: 'A finding from the specialist.' })).note_id;
  writeFileSync('probe.json', JSON.stringify(codes));
}

async function specialistTurn(member, say, text, scenario = {}) {
  let work;
  try { work = JSON.parse(text); } catch { work = undefined; }
  if (!work?.task_id) { say('Nothing to do: the prompt names no task.\n'); return; }
  if (scenario.probe) await probe(member, work.task_id);
  const { task } = await member.get(work.task_id);
  const artifact = `artifact_${randomBytes(6).toString('hex')}`;
  writeFileSync(`${artifact}.txt`, `Proposal for ${task.task_id}: ${task.objective}\n`);
  const receipt = await member.commit({ task_id: task.task_id, expected_revision: task.revision, operation_id: `propose:${task.task_id}:${member.member_id}`, transition: 'completed', result_ref: artifact });
  say(`Proposed ${artifact} for ${task.task_id} (${receipt.outcome} ${receipt.proposal_id ?? ''}).\n`);
}
