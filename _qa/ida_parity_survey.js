export const meta = {
  name: 'ida-parity-survey',
  description: 'Survey 12 dimensions where Hex-Rays/IDA output beats ours, with concrete gaps from real output, then rank a fix backlog',
  phases: [
    { title: 'Survey', detail: 'one auditor per IDA-strength dimension: find concrete gaps in real output' },
    { title: 'Rank', detail: 'synthesize + prioritize the fix backlog by frequency x severity x soundness-risk' },
  ],
}

const PAIRS = 'C:/Users/User/Downloads/sd/_qa/pairs'   // fn_*.txt : each has RAW DISASSEMBLY then `--- DECOMPILED ---` then our C
const ENGINE = 'C:/Users/User/Downloads/sd/engine/analysis/decompiler.cpp'

const COMMON = `
You are a Hex-Rays/IDA veteran auditing the output QUALITY of a custom x86-64 C decompiler.
Ground truth for "good" = what IDA Pro 8's Hex-Rays decompiler would emit for the same code.

EVIDENCE SOURCE: ${PAIRS}/fn_*.txt  (1445 files). Each file contains the RAW DISASSEMBLY,
then a line "--- DECOMPILED ---", then OUR emitted C for that function. Use Grep to find
functions exhibiting your dimension's patterns, then Read ~10-25 of them (both the disasm
and our C) to judge. You may also Read the emitter ${ENGINE} to locate the responsible code.

Your job: find CONCRETE, RECURRING places where our output reads worse than Hex-Rays would,
FOR YOUR ASSIGNED DIMENSION ONLY. For each gap, capture:
  - a real function (fn_XXXX) and the exact snippet of OUR output,
  - what Hex-Rays would emit instead (be specific and realistic — do NOT invent capabilities
    Hex-Rays lacks; e.g. Hex-Rays also keeps multi-use load temps and phi vars),
  - how often it occurs (grep a count across all 1445 if you can),
  - a root-cause hypothesis (which pass/emitter behavior causes it),
  - a fix approach, and the SOUNDNESS RISK of that fix (does it risk changing behavior?).

Hard rules:
  - Report only gaps you can SHOW with a real snippet. No speculation, no style-nitpicks that
    Hex-Rays wouldn't actually improve.
  - Distinguish IRREDUCIBLE (Hex-Rays does the same — e.g. genuine phi vars, multi-use loads,
    necessary reinterprets) from CLOSABLE. Only report CLOSABLE gaps.
  - This is a correctness-critical decompiler with behavioral gates; note if a fix is risky.`

const DIMENSIONS = [
  { key: 'naming', focus: `VARIABLE & TYPE NAMING. Hex-Rays: a1.. for args, v1.. for locals, 'result' for the returned value, and derives names from APIs/strings. Audit our temp names (t7, v3), whether we reuse the 'result' idiom, whether related temps get sane names. Grep for 't[0-9]' vs 'v[0-9]' density.` },
  { key: 'temps-cascade', focus: `TEMP MINIMIZATION. Surviving single-use side-effect-free temps that Hex-Rays would inline (t = a+b; use t once). Also bare copies (t = v;). Do NOT flag multi-use or multi-def temps (Hex-Rays keeps those too). Quantify how many single-use inlinable temps survive.` },
  { key: 'returns', focus: `RETURN SHAPE. Hex-Rays unifies to a single 'result' variable with one return, OR uses clean early-returns. Audit whether we emit awkward return forms: redundant (int)result casts, 'return (int)result;' where result is long long, split returns that should unify, or unified returns that should be early-returns.` },
  { key: 'casts-types', focus: `CAST NOISE & TYPE WIDTHS. Redundant/nested casts ((int)(unsigned int)x), unnecessary (int) around already-int exprs, wrong integer widths (int vs __int64), signedness churn. Hex-Rays keeps casts minimal. Grep for ')(unsigned' and '(int)(' patterns and count.` },
  { key: 'structs-fields', focus: `STRUCT/FIELD RECOVERY. Hex-Rays renders a1->field_10 or named members. Audit where we still emit raw *(_DWORD *)(a1 + 0x10) / *(int*)((char*)a1+off) instead of a1->field_off, and inconsistency (some fields recovered, some raw in the same fn).` },
  { key: 'controlflow', focus: `CONTROL-FLOW STRUCTURE. Residual gotos, missed loop forms (for/while/do-while), over-nested if/else, missed && / || short-circuit merges, missed 'continue'/'break', guard-clause inlining. Grep 'goto ' and 'while (' and 'switch (__state'. Note functions that read worse than Hex-Rays structuring.` },
  { key: 'idioms', focus: `IDIOM RECOGNITION. Hex-Rays recovers: division/modulo by constant (magic-number multiply), min/max, abs, memcpy/memset/strlen loops, bit rotate/popcount, sign-extension, boolean normalization (x!=0). Find raw idiom code we DIDN'T fold that Hex-Rays would.` },
  { key: 'signatures', focus: `FUNCTION SIGNATURES. Correct param count & types, return type, __fastcall. Audit fns where we drop/add params, wrong return type (void vs int vs pointer), 'int fun_x();' forward decls that Hex-Rays would type. Compare arg counts at call sites vs the callee prototype.` },
  { key: 'constants', focus: `CONSTANTS & LITERALS. Hex-Rays: hex for masks/addresses, decimal for counts, char constants ('A'), negative decimals for small negatives, recognizable flag ORs. Audit ugly constants: huge unsigned like 4294967295 instead of -1, 0x... where decimal is clearer or vice-versa, float literals.` },
  { key: 'pointers-arrays', focus: `POINTER/ARRAY EXPRESSIONS. Hex-Rays uses a1[i] indexing and clean pointer arithmetic. Audit clumsy *(T*)((char*)p + i*stride) where p[i] would read cleaner, missed array indexing, (char*) cast churn in address math.` },
  { key: 'globals-strings-api', focus: `GLOBAL/STRING/API REFERENCES. Hex-Rays shows string literals inline ("text"), named globals (dword_XXXX / real names), and imported API names via the IAT. Audit where we emit raw *(_QWORD*)0x14... or numeric addresses instead of a named/string reference.` },
  { key: 'booleans-compares', focus: `BOOLEAN & COMPARISON IDIOMS. Range checks (x>=lo && x<=hi), !ptr, ternary (a ? b : c) for cmov, boolean-returning funcs. Audit where we emit unsigned-subtract range checks, LODWORD/flag arithmetic, or nested if that Hex-Rays writes as one boolean expression.` },
  { key: 'deadcode-noise', focus: `DEAD CODE & NOISE. Unreachable statements, redundant self-assignments (v = v;), unused temps not DSE'd, empty blocks, labels with no gotos, no-op casts, doubled parentheses. Hex-Rays output is tight. Quantify noise lines.` },
]

const GAP_SCHEMA = {
  type: 'object',
  properties: {
    dimension: { type: 'string' },
    overall: { type: 'string', description: '2-3 sentences: how far are we from Hex-Rays on this dimension overall?' },
    gaps: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'short name of the gap' },
          example_fn: { type: 'string', description: 'fn_XXXX where it shows' },
          our_output: { type: 'string', description: 'exact snippet of OUR C' },
          hexrays_output: { type: 'string', description: 'what Hex-Rays would emit instead' },
          frequency: { type: 'string', description: 'count or estimate across the 1445 fns' },
          root_cause: { type: 'string', description: 'which pass/emitter behavior causes it' },
          fix_approach: { type: 'string', description: 'concrete fix' },
          soundness_risk: { type: 'string', enum: ['none', 'low', 'medium', 'high'] },
          impact: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['title', 'example_fn', 'our_output', 'hexrays_output', 'frequency', 'root_cause', 'fix_approach', 'soundness_risk', 'impact'],
      },
    },
  },
  required: ['dimension', 'overall', 'gaps'],
}

phase('Survey')
const surveys = await parallel(DIMENSIONS.map((d) => () =>
  agent(
    `${COMMON}\n\n==== YOUR DIMENSION: ${d.key} ====\n${d.focus}\n\nProduce the gap schema. Aim for the 3-8 highest-impact, real, CLOSABLE gaps. Empty gaps array is fine if we already match Hex-Rays here.`,
    { label: `survey:${d.key}`, phase: 'Survey', schema: GAP_SCHEMA, effort: 'high' }
  )
)).then((rs) => rs.filter(Boolean))

phase('Rank')
const flat = surveys.flatMap((s) => (s.gaps || []).map((g) => ({ ...g, dimension: s.dimension })))
const RANK_SCHEMA = {
  type: 'object',
  properties: {
    executive_summary: { type: 'string', description: 'where we stand vs Hex-Rays overall, and the 3-5 themes that matter most' },
    backlog: {
      type: 'array',
      description: 'the prioritized fix backlog, best-ROI first',
      items: {
        type: 'object',
        properties: {
          rank: { type: 'integer' },
          title: { type: 'string' },
          dimension: { type: 'string' },
          why: { type: 'string', description: 'frequency x impact x soundness-risk reasoning' },
          example: { type: 'string', description: 'fn_XXXX: our -> hexrays' },
          fix_approach: { type: 'string' },
          soundness_risk: { type: 'string', enum: ['none', 'low', 'medium', 'high'] },
          effort: { type: 'string', enum: ['small', 'medium', 'large'] },
        },
        required: ['rank', 'title', 'dimension', 'why', 'fix_approach', 'soundness_risk', 'effort'],
      },
    },
  },
  required: ['executive_summary', 'backlog'],
}
const ranked = await agent(
  `You are the lead engineer triaging an IDA-parity fix backlog for a correctness-critical decompiler. Below are ${flat.length} candidate gaps found across 12 dimensions by specialist auditors. Merge duplicates, drop any that Hex-Rays wouldn't actually improve or that are too risky for the behavioral gates, and produce a PRIORITIZED backlog best-ROI-first. Favor high-frequency, high-impact, LOW-soundness-risk fixes near the top (this codebase just had 13 correctness regressions from over-aggressive inlining — readability must never cost correctness). Give a crisp executive summary of where we stand vs Hex-Rays.\n\nCANDIDATE GAPS (JSON):\n${JSON.stringify(flat, null, 1).slice(0, 60000)}`,
  { label: 'rank:synthesis', phase: 'Rank', schema: RANK_SCHEMA, effort: 'high' }
)

return { dimensions_surveyed: surveys.length, total_gaps: flat.length, ranked, raw_by_dimension: surveys }
