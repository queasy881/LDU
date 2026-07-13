export const meta = {
  name: 'nullware-deep-read-100d',
  description: 'Deep-read 100 NullWare decompiled functions, classify real decompiler bugs with disasm evidence',
  phases: [
    { title: 'Read', detail: 'one agent per function reads full disasm+decompile, reports bugs' },
  ],
}

const FILES = ["fn_00001360.txt","fn_000013d0.txt","fn_00002490.txt","fn_000026d0.txt","fn_00005170.txt","fn_00005780.txt","fn_00005e60.txt","fn_00005f50.txt","fn_00006720.txt","fn_000077d0.txt","fn_00008230.txt","fn_00008730.txt","fn_00008a40.txt","fn_000090a0.txt","fn_00009350.txt","fn_0000bc40.txt","fn_0000c530.txt","fn_0000c9d0.txt","fn_0000cc50.txt","fn_0000d190.txt","fn_0000d650.txt","fn_0000d9f0.txt","fn_0000de00.txt","fn_0000e0a0.txt","fn_0000e390.txt","fn_0000e7a0.txt","fn_0000ea70.txt","fn_0000ef40.txt","fn_0000f590.txt","fn_0000fae0.txt","fn_000107a0.txt","fn_00010f20.txt","fn_000119d0.txt","fn_00011bb0.txt","fn_00011e40.txt","fn_000121c0.txt","fn_000122c0.txt","fn_000123f0.txt","fn_00012560.txt","fn_00012810.txt","fn_000129e0.txt","fn_00012bd0.txt","fn_00012eb0.txt","fn_000130c0.txt","fn_00013610.txt","fn_00013f10.txt","fn_00014010.txt","fn_000142c0.txt","fn_00014510.txt","fn_00014b00.txt","fn_00014f10.txt","fn_00015140.txt","fn_00015370.txt","fn_000154d0.txt","fn_000156d0.txt","fn_00015c20.txt","fn_00016260.txt","fn_000166d0.txt","fn_00016810.txt","fn_00016cb0.txt","fn_000172d0.txt","fn_000175a0.txt","fn_00018b40.txt","fn_00019830.txt","fn_0001ab40.txt","fn_0001c360.txt","fn_0001c530.txt","fn_0001c8a0.txt","fn_0001cad0.txt","fn_0001cd30.txt","fn_0001d2c0.txt","fn_0001dba0.txt","fn_0001e870.txt","fn_0001f990.txt","fn_000203a0.txt","fn_00020b40.txt","fn_00020d90.txt","fn_00021140.txt","fn_000213b0.txt","fn_00021740.txt","fn_00021820.txt","fn_00021b60.txt","fn_00021ef0.txt","fn_00022c40.txt","fn_00023100.txt","fn_000246d0.txt","fn_00025690.txt","fn_00026f60.txt","fn_00027310.txt","fn_00027740.txt","fn_000279b0.txt","fn_00027c30.txt","fn_00027df0.txt","fn_000280f0.txt","fn_000283b0.txt","fn_00028580.txt","fn_000287d0.txt","fn_00028b90.txt","fn_00029650.txt","fn_00029f30.txt"]
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
