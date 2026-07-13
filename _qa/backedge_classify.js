export const meta = {
  name: 'backedge-classify',
  description: 'Classify single-residual-goto functions: genuinely irreducible SCC vs reducible loop the detector missed',
  phases: [{ title: 'Classify' }],
}

const PAIRS = String.raw`C:\Users\User\Downloads\sd\_qa\pairs`;
let TARGETS = args;
if (typeof TARGETS === 'string') { try { TARGETS = JSON.parse(TARGETS); } catch (e) { TARGETS = []; } }
if (!Array.isArray(TARGETS)) TARGETS = [];
const BATCHES = [];
for (let i = 0; i < TARGETS.length; i += 4) BATCHES.push(TARGETS.slice(i, i + 4));

const SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' },
          classification: { type: 'string', enum: ['GENUINELY_IRREDUCIBLE', 'REDUCIBLE_LOOP_MISSED', 'OTHER'] },
          scc_entry_count: { type: 'integer' },
          pattern: { type: 'string' },
          goto_vs_sm: { type: 'string', enum: ['GOTO_MORE_READABLE', 'SM_MORE_READABLE', 'EQUAL'] },
          reducible_fix_hint: { type: 'string' },
        },
        required: ['file', 'classification', 'scc_entry_count', 'pattern', 'goto_vs_sm'],
      },
    },
  },
  required: ['results'],
};

const prompt = (batch) => `You analyze a C decompiler's control-flow recovery. Each function below has a "--- DISASM ---" (x86-64 truth) and "--- DECOMPILED ---" (recovered C) section, and the C contains EXACTLY ONE residual \`goto\` (a backward goto to a label). Determine WHY the structurer left that one goto instead of a clean loop.

For each function, build the CFG from the disasm (blocks + jump edges). Find the strongly-connected region (loop) the goto's edge belongs to. Classify:

- GENUINELY_IRREDUCIBLE: the loop region has 2+ distinct ENTRY points from outside (e.g. strcmp that enters a byte-align loop OR a qword-scan loop depending on alignment, and the two loops cross-jump into each other). A single-header while CANNOT express this without node duplication or a state variable. scc_entry_count >= 2.
- REDUCIBLE_LOOP_MISSED: the region has a SINGLE entry (one header dominates the whole loop), IS expressible as a normal while/for, but the loop detector failed to recognize it. scc_entry_count == 1; explain in reducible_fix_hint why the detector likely missed it (extra predecessor on the header, latch not identified, follow computed so a second loop nests as a sibling, etc).
- OTHER.

Also judge goto_vs_sm: is the current output (structured loops + one well-placed goto, Hex-Rays style) MORE readable than a flat \`while(1) switch(__state)\` state machine? For genuinely-irreducible SCCs the goto is usually far more readable -> GOTO_MORE_READABLE.

Read each file FULLY. Files in ${PAIRS}:
${batch.map(b => `- ${b.file} (${b.size} bytes, ${b.blocks} blocks)`).join('\n')}`;

phase('Classify');
const results = await parallel(BATCHES.map((batch, i) => () =>
  agent(prompt(batch), { label: `classify:b${i}`, phase: 'Classify', schema: SCHEMA, agentType: 'Explore' })
));

const all = results.filter(Boolean).flatMap(r => r.results || []);
const byClass = {};
for (const r of all) byClass[r.classification] = (byClass[r.classification] || 0) + 1;
const gotoReadable = all.filter(r => r.goto_vs_sm === 'GOTO_MORE_READABLE').length;
log(`classified ${all.length}: ${JSON.stringify(byClass)}; goto-more-readable=${gotoReadable}`);
return { total: all.length, byClass, gotoReadable, details: all };
