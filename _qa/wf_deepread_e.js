export const meta = {
  name: 'nullware-deep-read-100e',
  description: 'Deep-read 100 NullWare decompiled functions, classify real decompiler bugs with disasm evidence',
  phases: [
    { title: 'Read', detail: 'one agent per function reads full disasm+decompile, reports bugs' },
  ],
}

const FILES = ["fn_0002aef0.txt","fn_0002b090.txt","fn_0002b110.txt","fn_0002b210.txt","fn_0002b280.txt","fn_0002b320.txt","fn_0002b390.txt","fn_0002b400.txt","fn_0002b510.txt","fn_0002b5d0.txt","fn_0002b720.txt","fn_0002b790.txt","fn_0002b7f0.txt","fn_0002b870.txt","fn_0002b8e0.txt","fn_0002b910.txt","fn_0002b9d0.txt","fn_0002bb60.txt","fn_0002bc20.txt","fn_0002bf60.txt","fn_0002c240.txt","fn_0002c3d0.txt","fn_0002c6b0.txt","fn_0002c920.txt","fn_0002caa0.txt","fn_0002cb40.txt","fn_0002cdb0.txt","fn_0002cf40.txt","fn_0002d120.txt","fn_0002d310.txt","fn_0002d480.txt","fn_0002d5b0.txt","fn_0002d860.txt","fn_0002d9b0.txt","fn_0002db90.txt","fn_0002dd70.txt","fn_0002e1c0.txt","fn_0002e620.txt","fn_0002e720.txt","fn_0002e850.txt","fn_0002e8e0.txt","fn_0002e990.txt","fn_0002eae0.txt","fn_0002ede0.txt","fn_0002eeb0.txt","fn_0002ef40.txt","fn_0002f020.txt","fn_0002f090.txt","fn_0002f240.txt","fn_0002f2e0.txt","fn_0002f630.txt","fn_0002f7b0.txt","fn_0002fa00.txt","fn_0002fb10.txt","fn_00030010.txt","fn_00030060.txt","fn_00030320.txt","fn_000306d0.txt","fn_00030a30.txt","fn_00031590.txt","fn_00031760.txt","fn_00031b50.txt","fn_00031fd0.txt","fn_00032360.txt","fn_00032400.txt","fn_00032790.txt","fn_000327d0.txt","fn_00032830.txt","fn_00032980.txt","fn_00032a30.txt","fn_00032b60.txt","fn_00032bf0.txt","fn_00032dd0.txt","fn_00032ed0.txt","fn_000331e0.txt","fn_000333e0.txt","fn_000339b0.txt","fn_00034190.txt","fn_00034290.txt","fn_00034370.txt","fn_000344e0.txt","fn_00034ef0.txt","fn_00034f80.txt","fn_00035110.txt","fn_000351d0.txt","fn_000354c0.txt","fn_00035690.txt","fn_000356d0.txt","fn_00035830.txt","fn_000358e0.txt","fn_00035970.txt","fn_000359e0.txt","fn_00035a30.txt","fn_00035b70.txt","fn_00035cb0.txt","fn_00035d70.txt","fn_00035e20.txt","fn_00035e80.txt","fn_00035ee0.txt","fn_0005fc6c.txt"]
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
