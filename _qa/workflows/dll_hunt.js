export const meta = {
  name: 'dll-whole-fn-hunt',
  description: 'Deep-read WHOLE decompiled functions of a DLL vs disasm, find real bugs, adversarially verify',
  phases: [
    { title: 'Audit', detail: 'read whole functions, flag semantic mismatches' },
    { title: 'Verify', detail: 'adversarial disasm re-check per finding' },
  ],
}

const PAIRS = '_qa/out/pairs';
let TARGETS = args;
if (typeof TARGETS === 'string') { try { TARGETS = JSON.parse(TARGETS); } catch (e) { TARGETS = []; } }
if (!Array.isArray(TARGETS)) TARGETS = [];

// batch ~5 functions per auditor
const BATCHES = [];
for (let i = 0; i < TARGETS.length; i += 5) BATCHES.push(TARGETS.slice(i, i + 5));

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          defect_class: { type: 'string' },
          summary: { type: 'string' },
          disasm_evidence: { type: 'string', description: 'the EXACT disasm instruction(s) the C contradicts' },
          decompiled_snippet: { type: 'string' },
          expected: { type: 'string' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['file', 'defect_class', 'summary', 'disasm_evidence', 'decompiled_snippet', 'expected', 'confidence'],
      },
    },
  },
  required: ['findings'],
};

const VERDICT = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['REAL_BUG', 'FAITHFUL_TO_BINARY', 'UNCERTAIN'] },
    reason: { type: 'string' },
    root_cause_hint: { type: 'string' },
  },
  required: ['verdict', 'reason'],
};

const auditPrompt = (batch) => `You audit a decompiler's output for CORRECTNESS bugs. Read each function's FULL "--- DISASM ---" (x86-64 truth) and FULL "--- DECOMPILED ---" (recovered C) sections and compare them instruction by instruction. Do NOT skim — read the WHOLE function.

A finding is a place where the C computes a DIFFERENT value / takes a different branch / drops a store / mis-recovers a value than the disasm — a genuine semantic bug, NOT verbose-but-correct code, NOT a faithful rendering of untyped struct access or unusual idioms (a NaN self-compare \`x!=x\` on a float is CORRECT).

Hunt especially for: dropped memory stores (esp. xchg/cmpxchg/atomic/movnt), wrong signedness or width (sar vs shr, movsx vs movzx, missing sign/zero-extend), inverted or wrong-signedness compares (ja/jae unsigned rendered signed), call sites dropping arguments, cmov/setcc not modeled, pointer-scaling errors, lost register values rendered as a stray constant, off-by-one loop bounds, a value used before its definition.

For each candidate, cite the EXACT disasm instruction it contradicts. Report up to 8 highest-confidence findings across the batch; empty list if all are faithful.

Files in ${PAIRS} (read each FULLY, use offset/limit reads for large ones):
${batch.map(b => `- ${b.file} (${b.size} bytes, ${b.blocks} blocks)`).join('\n')}`;

phase('Audit');
const results = await pipeline(
  BATCHES,
  (batch, _orig, i) => agent(auditPrompt(batch), { label: `audit:batch${i}`, phase: 'Audit', schema: FINDINGS, agentType: 'Explore' }),
  (found) => {
    const list = (found && found.findings) ? found.findings : [];
    return parallel(list.map(fd => () =>
      agent(
        `Adversarially verify ONE decompiler finding. Default to FAITHFUL_TO_BINARY unless you can PROVE the C miscompiles the disasm.

File: ${PAIRS}\\${fd.file}
Claimed defect (${fd.defect_class}): ${fd.summary}
Wrong C: ${fd.decompiled_snippet}
Cited disasm: ${fd.disasm_evidence}
Expected: ${fd.expected}

Read the file's DISASM and DECOMPILED yourself, execute the relevant instructions by hand, decide REAL_BUG / FAITHFUL_TO_BINARY / UNCERTAIN, and give a concrete triggering input/state if REAL_BUG.`,
        { label: `verify:${fd.file}`, phase: 'Verify', schema: VERDICT, agentType: 'Explore' }
      ).then(v => ({ ...fd, verdict: v && v.verdict, verify_reason: v && v.reason, root_cause_hint: v && v.root_cause_hint }))
    ));
  }
);

const all = results.flat().filter(Boolean);
const real = all.filter(x => x.verdict === 'REAL_BUG');
const uncertain = all.filter(x => x.verdict === 'UNCERTAIN');
log(`hunt: ${TARGETS.length} fns, ${all.length} candidates, ${real.length} REAL_BUG, ${uncertain.length} UNCERTAIN`);
return { audited: TARGETS.length, real_bugs: real, uncertain, total_candidates: all.length };
