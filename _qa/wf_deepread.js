export const meta = {
  name: 'nullware-deep-read-100',
  description: 'Deep-read 100 NullWare decompiled functions, classify real decompiler bugs with disasm evidence',
  phases: [
    { title: 'Read', detail: 'one agent per function reads full disasm+decompile, reports bugs' },
  ],
}

const FILES = ["fn_000012c0.txt","fn_00001370.txt","fn_00001710.txt","fn_000024a0.txt","fn_00004170.txt","fn_000052e0.txt","fn_000057d0.txt","fn_00005ef0.txt","fn_00006190.txt","fn_00006880.txt","fn_000079e0.txt","fn_000082e0.txt","fn_00008920.txt","fn_00008b80.txt","fn_000091c0.txt","fn_00009410.txt","fn_0000be30.txt","fn_0000c680.txt","fn_0000ca70.txt","fn_0000ccd0.txt","fn_0000d1f0.txt","fn_0000d6c0.txt","fn_0000db80.txt","fn_0000de10.txt","fn_0000e0b0.txt","fn_0000e470.txt","fn_0000e7d0.txt","fn_0000eb50.txt","fn_0000f0a0.txt","fn_0000f5a0.txt","fn_0000fd40.txt","fn_00010840.txt","fn_00011080.txt","fn_00011a10.txt","fn_00011c20.txt","fn_00012140.txt","fn_00012210.txt","fn_000122e0.txt","fn_00012460.txt","fn_00012610.txt","fn_00012890.txt","fn_000129f0.txt","fn_00012d10.txt","fn_00012ec0.txt","fn_00013270.txt","fn_00013750.txt","fn_00013f40.txt","fn_00014040.txt","fn_000142f0.txt","fn_00014a40.txt","fn_00014b50.txt","fn_00014f80.txt","fn_000151d0.txt","fn_000153b0.txt","fn_00015540.txt","fn_00015740.txt","fn_00015f30.txt","fn_00016490.txt","fn_00016770.txt","fn_000168c0.txt","fn_00016de0.txt","fn_00017320.txt","fn_000179e0.txt","fn_00018b70.txt","fn_00019b80.txt","fn_0001bcd0.txt","fn_0001c3e0.txt","fn_0001c570.txt","fn_0001c930.txt","fn_0001cb60.txt","fn_0001cdd0.txt","fn_0001d510.txt","fn_0001e0d0.txt","fn_0001eae0.txt","fn_0001fbe0.txt","fn_00020420.txt","fn_00020cd0.txt","fn_00020eb0.txt","fn_000211b0.txt","fn_00021420.txt","fn_00021780.txt","fn_00021840.txt","fn_00021c10.txt","fn_00021fa0.txt","fn_00022cf0.txt","fn_00023300.txt","fn_00024ad0.txt","fn_00025950.txt","fn_00026f90.txt","fn_00027490.txt","fn_000277d0.txt","fn_00027a70.txt","fn_00027ca0.txt","fn_00027e60.txt","fn_000281a0.txt","fn_00028460.txt","fn_000286a0.txt","fn_000289a0.txt","fn_000290d0.txt","fn_000299e0.txt"]
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
