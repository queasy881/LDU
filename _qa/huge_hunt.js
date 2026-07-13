export const meta = {
  name: 'huge-fn-deep-audit',
  description: 'Deep-audit the largest decompiled functions (one auditor each) vs disasm, adversarially verify',
  phases: [
    { title: 'Audit', detail: 'one deep auditor per huge function' },
    { title: 'Verify', detail: 'adversarial disasm re-check per finding' },
  ],
}

const PAIRS = String.raw`C:\Users\User\Downloads\sd\_qa\pairs`;
// args is an array of { file, blocks, size } for the huge functions to audit
// (tolerate a JSON-encoded string as well as a real array)
let TARGETS = args;
if (typeof TARGETS === 'string') { try { TARGETS = JSON.parse(TARGETS); } catch (e) { TARGETS = []; } }
if (!Array.isArray(TARGETS)) TARGETS = [];

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
          disasm_evidence: { type: 'string' },
          decompiled_snippet: { type: 'string' },
          expected: { type: 'string' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['file', 'defect_class', 'summary', 'disasm_evidence', 'decompiled_snippet', 'expected', 'confidence'],
      },
    },
    completeness: { type: 'string', description: 'did every disasm block appear in the C? any dropped code/goto-soup/uncompilable artifact?' },
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

const auditPrompt = (t) => `You are the sole auditor of ONE large decompiled function. Find CORRECTNESS bugs by comparing the recovered C to the ground-truth disassembly.

File: ${PAIRS}\\${t.file}   (${t.blocks} blocks, ${t.size} bytes)

The file has a "--- DISASM ---" section (x86-64 truth) and a "--- DECOMPILED ---" section (recovered C). Read BOTH in full (use offset/limit reads if large).

Hunt for genuine semantic divergences — the C computes a different value, takes a different branch, drops a store, or mis-recovers a value — NOT mere verbosity or ugly-but-correct idioms. Giant functions especially stress:
- register recovery across many blocks (a value that leaked / became a stray constant / wrong temp)
- big switch/jump-table dispatchers (case selector mapped to the wrong target)
- atomic ops (xchg/cmpxchg/lock) whose memory store must be present
- signed vs unsigned compares and shifts (ja/jae vs jg/jge; sar vs shr; movsx vs movzx)
- loop bounds and break/continue in nested loops
- memory stores dropped or mis-widthed
- COMPLETENESS: does every disasm basic block's effect appear in the C? Was any code dropped? Is the C compilable (no undeclared temp, no unresolved label)?

Verify each candidate against the exact disasm instruction before reporting. Report up to 10 highest-confidence findings; empty list if the function is faithfully decompiled. Also fill "completeness" with your judgment on whether all code is present and the C would compile.`;

phase('Audit');
const results = await pipeline(
  TARGETS,
  t => agent(auditPrompt(t), { label: `audit:${t.file}`, phase: 'Audit', schema: FINDINGS, agentType: 'Explore' })
        .then(r => ({ t, r })),
  ({ t, r }) => {
    const list = (r && r.findings) ? r.findings : [];
    return parallel(list.map(fd => () =>
      agent(
        `Adversarially verify ONE finding in a large decompiled function. Default to FAITHFUL_TO_BINARY unless you can PROVE the C miscompiles the disasm.

File: ${PAIRS}\\${fd.file}
Claimed defect (${fd.defect_class}): ${fd.summary}
Wrong C: ${fd.decompiled_snippet}
Cited disasm: ${fd.disasm_evidence}
Claimed correct form: ${fd.expected}

Read the file's DISASM and DECOMPILED yourself, execute the relevant instructions by hand, and decide REAL_BUG / FAITHFUL_TO_BINARY / UNCERTAIN. Give a concrete triggering input/state if REAL_BUG.`,
        { label: `verify:${fd.file}`, phase: 'Verify', schema: VERDICT, agentType: 'Explore' }
      ).then(v => ({ ...fd, verdict: v && v.verdict, verify_reason: v && v.reason, root_cause_hint: v && v.root_cause_hint }))
    )).then(vs => ({ completeness: { file: t.file, note: r && r.completeness }, verified: vs.filter(Boolean) }));
  }
);

const flat = results.filter(Boolean);
const allFindings = flat.flatMap(x => x.verified || []);
const real = allFindings.filter(x => x.verdict === 'REAL_BUG');
const uncertain = allFindings.filter(x => x.verdict === 'UNCERTAIN');
const completeness = flat.map(x => x.completeness).filter(c => c && c.note);
log(`huge-audit: ${TARGETS.length} fns, ${allFindings.length} candidates, ${real.length} REAL_BUG, ${uncertain.length} UNCERTAIN`);
return { real_bugs: real, uncertain, completeness, audited: TARGETS.length };
