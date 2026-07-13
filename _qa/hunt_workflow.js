export const meta = {
  name: 'semantic-defect-hunt',
  description: 'Fan out per-defect-class finders over 1443 decompiled NullWare fns, adversarially verify each vs disasm',
  phases: [
    { title: 'Hunt', detail: 'per-class finders grep+deep-read the dumps' },
    { title: 'Verify', detail: 'adversarial disasm check per candidate' },
  ],
}

const PAIRS = String.raw`C:\Users\User\Downloads\sd\_qa\pairs`;

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'e.g. fn_00012345.txt' },
          line: { type: 'integer', description: '1-indexed line in the DECOMPILED section' },
          defect_class: { type: 'string' },
          summary: { type: 'string', description: 'one sentence: what is wrong' },
          disasm_evidence: { type: 'string', description: 'the exact disasm instruction(s) that prove the C is wrong' },
          decompiled_snippet: { type: 'string', description: 'the wrong C line(s)' },
          expected: { type: 'string', description: 'what the C should have been' },
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
    reason: { type: 'string', description: 'why, citing the specific disasm semantics' },
    root_cause_hint: { type: 'string', description: 'if REAL_BUG, the likely decompiler root cause / defect class' },
  },
  required: ['verdict', 'reason'],
};

const base = (cls, guidance) => `You are auditing a decompiler's output for CORRECTNESS bugs of one class: ${cls}.

Each file in ${PAIRS}\\fn_<rva>.txt has a "--- DISASM ---" section (ground truth x86-64) and a "--- DECOMPILED ---" section (the recovered C). A finding is a place where the C computes something DIFFERENT from what the disasm does — a real semantic bug, NOT merely ugly/verbose code and NOT a faithful rendering of unusual-but-correct machine code.

${guidance}

Method:
1. Use Grep over ${PAIRS} to find candidate files matching your class's signature.
2. Read the DISASM and DECOMPILED of ~20-30 candidates. Prefer smaller functions (easier to verify fully).
3. For each candidate, mentally execute the relevant disasm and compare to the C. Only report if you can point to the EXACT disasm instruction that the C contradicts.
4. Be skeptical of yourself: stripped binaries have untyped struct access, pointer arithmetic on unknown layouts, and unusual idioms that LOOK wrong but are faithful. Those are NOT bugs. A NaN self-compare (x != x on a float) is CORRECT. Reserve findings for genuine miscompilations.

Return up to 8 of your HIGHEST-confidence findings. Fewer real findings beats many weak ones. If you find nothing solid, return an empty list.`;

const FINDERS = [
  { key: 'signedness-width', prompt: base('signedness & integer width',
    `Look for: a value declared/used unsigned where the disasm does a SIGNED operation (idiv/sar/movsx/js/jl/jg) or vice-versa; an arithmetic shift (sar) rendered as logical (>>) on unsigned or the reverse; a movsx/movzx whose sign-extension the C dropped (so a negative byte reads as large positive or vice-versa); a 32-bit operation whose result the C treats as 64-bit without the zero/sign-extend, or a truncation the C omitted.`) },
  { key: 'ptr-scaling', prompt: base('pointer-arithmetic scaling',
    `Look for: pointer arithmetic that scales an index twice or not at all — e.g. \`(char*)(&v + i*8)\` where \`&v + i*8\` already scales by sizeof, vs the correct \`(char*)&v + i*8\`; an element-size mismatch (\`*(int*)(p + i)\` where disasm indexes by i*4); a \`base[i]\` collapse that changed the effective address vs the disasm's \`[base + i*scale + disp]\`.`) },
  { key: 'wrong-const', prompt: base('wrong constant / dropped value',
    `Look for: an immediate in the C that differs from the disasm immediate (wrong mask, wrong displacement, wrong shift count); a value that should be a recovered register/temp but rendered as a stray small constant (0/1) because a def was lost; a fold that produced the wrong number (e.g. sign-extension of an immediate mishandled).`) },
  { key: 'control-flow', prompt: base('control-flow / condition correctness',
    `Look for: an \`if\` condition INVERTED vs the disasm's jcc (e.g. disasm \`jae\` but C uses \`<\`); a comparison using the wrong signedness (\`ja\` unsigned rendered as signed \`>\`); a loop bound off-by-one vs the disasm's cmp; a branch that lost its flags and folded to a constant condition; a switch/case selector that maps to the wrong case.`) },
  { key: 'mem-store', prompt: base('memory store / read-modify-write correctness',
    `Look for: a read-modify-write where the post-store value read back is wrong (\`*p = *p - 1; if (*p - 1 ...)\` double-decrement); a store whose WIDTH differs from the disasm (byte store rendered as int); a store that was dropped entirely; a swap/exchange through memory that clobbered a value; a writeback to an out-parameter that was lost.`) },
  { key: 'deep-audit', prompt: base('any semantic mismatch (deep read of complex fns)',
    `Read the LARGEST / most-block-heavy functions (grep the "=== fun_... blocks=N ===" headers, pick high N). Deep-read a handful end to end and flag ANY line where the C does not match the disasm's computation, of any kind. This is the catch-all for classes the other finders miss.`) },
];

phase('Hunt');
const results = await pipeline(
  FINDERS,
  f => agent(f.prompt, { label: `hunt:${f.key}`, phase: 'Hunt', schema: FINDINGS, agentType: 'Explore' }),
  (found, f) => {
    const list = (found && found.findings) ? found.findings : [];
    return parallel(list.map(fd => () =>
      agent(
        `Adversarially verify ONE decompiler-output finding. Default to FAITHFUL_TO_BINARY unless you can PROVE the C miscompiles the disasm.

File: ${PAIRS}\\${fd.file}
Claimed defect (${fd.defect_class}): ${fd.summary}
Wrong C: ${fd.decompiled_snippet}
Cited disasm: ${fd.disasm_evidence}
Claimed correct form: ${fd.expected}

Read the file's DISASM and DECOMPILED sections yourself. Execute the relevant instructions by hand. Decide:
- REAL_BUG: the C provably computes a different value/branch than the disasm, on some concrete input.
- FAITHFUL_TO_BINARY: the C matches the disasm (the finding is a false positive — untyped-but-correct, verbose-but-correct, or a legit idiom like NaN self-compare).
- UNCERTAIN: cannot determine from the dump alone.
Give a concrete input or state that triggers the divergence if REAL_BUG.`,
        { label: `verify:${fd.file}:${fd.defect_class}`, phase: 'Verify', schema: VERDICT, agentType: 'Explore' }
      ).then(v => ({ ...fd, verdict: v && v.verdict, verify_reason: v && v.reason, root_cause_hint: v && v.root_cause_hint }))
    ));
  }
);

const all = results.flat().filter(Boolean);
const real = all.filter(x => x.verdict === 'REAL_BUG');
const uncertain = all.filter(x => x.verdict === 'UNCERTAIN');
log(`hunt complete: ${all.length} candidates, ${real.length} REAL_BUG, ${uncertain.length} UNCERTAIN`);
return { real_bugs: real, uncertain, total_candidates: all.length };
