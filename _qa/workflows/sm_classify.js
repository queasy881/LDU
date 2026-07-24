export const meta = {
  name: 'sm-classify',
  description: 'Classify each small state-machine function: reducible (structurer bug) vs genuinely irreducible, and name the pattern',
  phases: [{ title: 'Classify', detail: 'reconstruct CFG from disasm, judge reducibility + pattern' }],
}

const PAIRS = '_qa/out/pairs';
let ITEMS = args;
if (typeof ITEMS === 'string') { try { ITEMS = JSON.parse(ITEMS); } catch (e) { ITEMS = []; } }
if (!Array.isArray(ITEMS)) ITEMS = [];

// batch into groups of 6
const BATCHES = [];
for (let i = 0; i < ITEMS.length; i += 6) BATCHES.push(ITEMS.slice(i, i + 6));

const SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' },
          verdict: { type: 'string', enum: ['STRUCTURABLE', 'IRREDUCIBLE', 'UNCERTAIN'] },
          pattern: { type: 'string', description: 'short category, e.g. shared-exit-goto, jump-table-switch, loop-precheck-guard, multi-exit-loop, nested-loop-break, irreducible-multi-entry-loop' },
          difficulty: { type: 'string', enum: ['SINGLE_LEVEL_FIXABLE', 'NEEDS_MULTILEVEL', 'IRREDUCIBLE_MULTI_ENTRY'], description: 'SINGLE_LEVEL_FIXABLE = a normal reducible pattern (single loop, guard, shared exit, switch) a good structurer emits with plain if/else/while/break/continue. NEEDS_MULTILEVEL = requires breaking/continuing an OUTER loop from inside an inner loop (C needs a goto or a boolean flag). IRREDUCIBLE_MULTI_ENTRY = a loop entered at 2+ blocks (genuinely needs a state machine).' },
          reason: { type: 'string', description: 'the specific CFG feature: loop header block(s), entry count, the cross-loop jump target, etc.' },
        },
        required: ['file', 'verdict', 'pattern', 'difficulty', 'reason'],
      },
    },
  },
  required: ['results'],
};

const prompt = (batch) => `You are a control-flow-analysis expert auditing a decompiler that fell back to a \`while(1) switch(__state)\` STATE MACHINE for these functions. A state machine is ONLY justified for an IRREDUCIBLE control-flow graph — a loop with MORE THAN ONE entry point (no single header). Everything else is a structurer BUG: the function is reducible and should have been recovered as nested if/else/while/for/switch.

For EACH file below, read its "--- DISASM ---" section in ${PAIRS}, reconstruct the basic-block CFG (leaders = jump targets + fall-throughs after a jump; edges = jcc taken/fall, jmp, call-then-fall), find the loops and their ENTRY points, and decide:

- **IRREDUCIBLE** — there is a loop you can enter at two different blocks (two edges from outside the loop targeting two different loop blocks). Only THIS genuinely needs a state machine. Rare.
- **STRUCTURABLE** — every loop has a single entry (reducible). The state machine is a structurer bug. Name the PATTERN that likely defeated it: e.g.
   • \`jump-table-switch\` — an indirect \`jmp reg\` off a table (a big switch); each case a tiny block.
   • \`shared-exit-goto\` — a common exit/error block (often ending in a \`call\`+\`ret\` or \`int3\`) reached from 3+ sites; should be duplicated or made a guard clause.
   • \`loop-precheck-guard\` — \`cmp;je exit; body; cmp;jne body\` (a while/do-while behind a guard).
   • \`multi-exit-loop\` — a single-entry loop with 2+ exit edges to different targets.
   • \`nested-loop-break\` — break/continue to a non-innermost loop.
   • \`short-circuit-chain\` — a chain of \`cmp;jcc\` to the same target (should be &&/||).
   Pick the closest; invent a short name if none fit.
- **UNCERTAIN** — can't reconstruct from the dump.

Files (read each fully):
${batch.map(b => `- ${b.file} (${b.blocks} blocks)`).join('\n')}

Be rigorous: actually trace the edges. Most of these ARE structurable — find the specific reason. Return one result per file.`;

phase('Classify');
const results = await parallel(BATCHES.map((batch, i) => () =>
  agent(prompt(batch), { label: `classify:batch${i}`, phase: 'Classify', schema: SCHEMA, agentType: 'Explore' })
    .then(r => (r && r.results) ? r.results : [])
));

const all = results.filter(Boolean).flat();
const byPattern = {};
const byDifficulty = {};
for (const r of all) {
  byPattern[r.pattern] = (byPattern[r.pattern] || 0) + 1;
  byDifficulty[r.difficulty] = (byDifficulty[r.difficulty] || 0) + 1;
}
const fixable = all.filter(r => r.difficulty === 'SINGLE_LEVEL_FIXABLE');
log(`classified ${all.length}: byDifficulty=${JSON.stringify(byDifficulty)}`);
return { total: all.length, byDifficulty, byPattern, fixable, classifications: all };
