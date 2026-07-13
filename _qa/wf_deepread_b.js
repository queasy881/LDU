export const meta = {
  name: 'nullware-deep-read-100b',
  description: 'Deep-read 100 NullWare decompiled functions, classify real decompiler bugs with disasm evidence',
  phases: [
    { title: 'Read', detail: 'one agent per function reads full disasm+decompile, reports bugs' },
  ],
}

const FILES = ["fn_00001310.txt","fn_000013b0.txt","fn_000023c0.txt","fn_00002630.txt","fn_00004ac0.txt","fn_00005700.txt","fn_00005b80.txt","fn_00005f30.txt","fn_000062c0.txt","fn_00006aa0.txt","fn_00007cb0.txt","fn_00008700.txt","fn_000089e0.txt","fn_00008ed0.txt","fn_00009250.txt","fn_00009550.txt","fn_0000c2e0.txt","fn_0000c7f0.txt","fn_0000cb50.txt","fn_0000d0b0.txt","fn_0000d5a0.txt","fn_0000d940.txt","fn_0000dd50.txt","fn_0000e080.txt","fn_0000e210.txt","fn_0000e6f0.txt","fn_0000e880.txt","fn_0000ee20.txt","fn_0000f2e0.txt","fn_0000fa20.txt","fn_000103a0.txt","fn_00010a90.txt","fn_00011790.txt","fn_00011b40.txt","fn_00011d10.txt","fn_00012180.txt","fn_000122b0.txt","fn_00012370.txt","fn_000124d0.txt","fn_000127b0.txt","fn_000129c0.txt","fn_00012b00.txt","fn_00012ea0.txt","fn_00013010.txt","fn_00013490.txt","fn_00013e50.txt","fn_00013ff0.txt","fn_00014290.txt","fn_00014400.txt","fn_00014ae0.txt","fn_00014e60.txt","fn_00015130.txt","fn_00015300.txt","fn_00015420.txt","fn_00015610.txt","fn_00015920.txt","fn_000160d0.txt","fn_00016690.txt","fn_000167c0.txt","fn_000169f0.txt","fn_00017260.txt","fn_00017560.txt","fn_00017ee0.txt","fn_00019580.txt","fn_0001aa90.txt","fn_0001be90.txt","fn_0001c500.txt","fn_0001c630.txt","fn_0001ca50.txt","fn_0001cc90.txt","fn_0001d260.txt","fn_0001da50.txt","fn_0001e5f0.txt","fn_0001f240.txt","fn_000202f0.txt","fn_00020a20.txt","fn_00020d00.txt","fn_00021040.txt","fn_000213a0.txt","fn_00021690.txt","fn_000217e0.txt","fn_00021b10.txt","fn_00021dd0.txt","fn_00022b50.txt","fn_00022ec0.txt","fn_000240c0.txt","fn_000254f0.txt","fn_00026e80.txt","fn_00027230.txt","fn_000276e0.txt","fn_00027940.txt","fn_00027bd0.txt","fn_00027d80.txt","fn_00028040.txt","fn_00028300.txt","fn_000284d0.txt","fn_000287b0.txt","fn_00028ab0.txt","fn_00029280.txt","fn_00029dd0.txt"]
const DIR = 'C:\\Users\\User\\Downloads\\sd\\_qa\\pairs\\'

const SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['rva', 'verdict', 'findings'],
  properties: {
    rva: { type: 'string', description: 'function RVA hex e.g. 0x12c0' },
    verdict: { type: 'string', enum: ['clean', 'has_real_bug', 'cosmetic_only'] },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['severity', 'category', 'description', 'evidence', 'root_cause'],
        properties: {
          severity: { type: 'string', enum: ['critical', 'major', 'minor', 'cosmetic'] },
          category: { type: 'string', description: 'short tag e.g. float-into-int, wrong-sign, dropped-body, partial-reg-or, wrong-arg-count, ptr-mistype, missing-cast, struct-return, bad-structure' },
          description: { type: 'string' },
          evidence: { type: 'string', description: 'the decompiled line AND the disasm line(s) proving it wrong' },
          root_cause: { type: 'string' },
        },
      },
    },
  },
}

const results = await pipeline(
  FILES,
  (fname) => agent(
    `You are auditing one decompiled function from a real Windows DLL (NullWare.dll), produced by a decompiler under active development that aims for IDA Pro / Hex-Rays quality.

Read the ENTIRE file at "${DIR}${fname}" — it contains the function's full x86-64 DISASSEMBLY followed by the decompiler's pseudo-C output. Read every line of both.

Your job: find places where the decompiled C is WRONG or MISLEADING versus what the disassembly actually does. Be a rigorous adversarial reviewer, but ALSO be precise about what is a genuine decompiler defect vs. faithful decompilation of unusual-but-correct code.

Classify each finding:
- REAL decompiler bug (the C does NOT match the asm, or would misbehave/miscompile): float stored through int* (truncation), wrong signedness, a register-tracked value dropped, branch bodies emitted as empty {} when the asm does work, wrong argument count to a call, a pointer mistyped (e.g. double* for a struct base), a missing cast that breaks compilation, mis-paired operands (verify arithmetic operand pairing against the actual instruction operands and register reuse!), wrong return type, broken/illegible control structure (state-machine switch(__state) instead of real loops), etc.
- NOT a bug (do not report, or mark cosmetic): a hardcoded absolute address like *(...)0x174148 (faithful — that is a real global), an 'unsigned char' boolean return, redundant-but-correct recomputation, verbose-but-correct partial-register modeling with & -65536 / & 0xffff, K&R empty () prototypes.

CRITICAL: verify arithmetic by tracing register values through the disasm (watch for register REUSE / reloads between a load and the op that consumes it — a value loaded into xmmN may be overwritten before use). Do not claim "garbled pairing" without proving it from the operand registers.

Only report findings you can back with specific disasm evidence. If the function is correct, return verdict "clean" with an empty findings array. If only cosmetic issues, verdict "cosmetic_only". Quote the exact decompiled line and the exact disasm line(s) in 'evidence'.`,
    { label: `read:${fname.replace('fn_','').replace('.txt','')}`, phase: 'Read', schema: SCHEMA, agentType: 'Explore' }
  )
)

const ok = results.filter(Boolean)
const withBugs = ok.filter(r => r.verdict === 'has_real_bug')
const cats = {}
for (const r of ok) for (const f of (r.findings||[])) {
  if (f.severity === 'cosmetic') continue
  const k = f.category || 'misc'
  if (!cats[k]) cats[k] = []
  cats[k].push({ rva: r.rva, severity: f.severity, description: f.description, evidence: f.evidence, root_cause: f.root_cause })
}
const catSummary = Object.entries(cats)
  .map(([k, v]) => ({ category: k, count: v.length, severities: v.map(x=>x.severity), items: v }))
  .sort((a,b)=>b.count-a.count)

log(`audited ${ok.length}/${FILES.length}; ${withBugs.length} with real bugs; ${Object.keys(cats).length} non-cosmetic categories`)

return {
  audited: ok.length,
  with_real_bugs: withBugs,
  category_clusters: catSummary,
}
