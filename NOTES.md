# Working notes

Running log of what is being worked on, what was just fixed, and what is known
to still be broken. Newest first. This is a status file, not documentation —
the reasoning behind each change lives in its commit message.

---

## In progress: Rust binaries print the WRONG string literal

**Status: diagnosed, not yet fixed. This is a correctness bug, not cosmetics.**

Rust's `&str` is a `(pointer, length)` pair, and its literals are packed into
`.rdata` back-to-back **with no NUL terminators**. Confirmed in
`target/release/disasmstudio.exe`, where one 25-byte run

```
\n}[{,\n: ]"falsetruenull,:
```

is the backing store for `"\n"`, `"}"`, `"["`, `"{"`, `","`, `": "`, `"]"`,
`"\""`, `"false"`, `"true"`, `"null"` and `","` — every one of them addressed as
an offset plus a length into that single run.

`read_cstring` assumes C semantics and reads to the next NUL, so it runs straight
off the end of the intended literal and into its neighbours. Real output from
`fn_0007ee10` (a serde_json deserializer):

| emitted | length arg | actually means |
|---|---|---|
| `"truenull,:"` | 4 | `"true"` |
| `"falsetruenull,:"` | 5 | `"false"` |
| `"{,\n: ]\"falsetruenull,:"` | 1 | `"{"` |

The length is sitting right there in the next argument. This is worse than
printing a bare address: it is a confident, wrong answer.

**Why it is not fixed yet.** The obvious rule — "truncate a string argument to the
integer argument that follows it" — breaks C. `strncmp(s, "hello", 3)` would start
rendering `"hel"`, which is equally wrong in the other direction. The two cases
are locally indistinguishable: in both, the byte at `ptr + len` is not a NUL.

The intended fix is to gate the slice interpretation on the image actually being
a Rust binary, so nothing about C output can change. Candidate markers (`/rustc/`,
`library\std\src\`, `RUST_BACKTRACE`, `core::panicking`, `rust_begin_unwind`) were
being checked against a Rust binary, kernel32, ntdll and a Go binary when this
note was written; the marker has to hit the Rust image and miss all three others.
The engine already has `analysis/rust_demangle.cpp`, so Rust awareness is not new
here — there is just no "is this a Rust image" flag yet.

## Also open: Rust goto density

`disasmstudio.exe` produces 11,545 gotos across 377 functions; kernel32 produces
1,379 across 206. The gotos are concentrated — in a 1200-function sample, 300
functions hold all 9,549, and the top 8 hold ~2,900. The worst offenders are
`memchr`-style SIMD scanners and large `serde` deserializers.

Not yet established whether these are hitting the whole-function `emit_goto_cfg`
fallback, tripping the work budget, or are genuinely irreducible. Two of the top
offenders carry heavy `unmodeled ops` counts (`__pmovmskb`, `_mm_cmpeq_epi8`,
`_mm_shufflelo_epi16`, `_mm_unpacklo_epi8`) but one — `fn_0007ee10`, 324 gotos —
has none, so unmodeled SIMD is not the whole story.

---

## Done

### Go function names from the embedded pclntab (`4846958`)

Statically-linked Go exports almost nothing, so git-lfs was 12,465 functions all
named `fun_<rva>`. Go ships its own symbol table in every release build
(`runtime.pclntab` — what the runtime uses for stack traces; not debug info, not
stripped). Parsing it gives real names, and because it runs before `build_cfg`
collects function starts, a name also *recovers* functions nothing calls.

```
fun_000d0480(...)        ->  syscall_init(...)
  fun_0001af40()               runtime_newobject()
  fun_000801a0()               runtime_mapassign_faststr()
  fun_0000d4c0()               syscall_GetStdHandle()
```

- 14,364 entries, 14,092 named; discovery 12,465 -> 14,409 functions
- go1.16 / go1.18 / go1.20 header generations handled; go1.2 deliberately not
- kernel32 / ntdll / a Rust binary: no false positive, 0 of 2590 kernel32
  functions changed

### Deep CFGs no longer crash the process (`5607907`)

A Go package-init function (324 chained `if` blocks) drove the structurer's
recursion past 140 frames and killed the process with `STATUS_ACCESS_VIOLATION`.
The GUI's workers run on 2 MiB stacks, so this was not a test artifact.

The ceiling is a **depth**, not a stack measurement, so output cannot depend on
which thread produced it. Hitting it **cuts that one region** and re-emits it at
top level rather than collapsing the whole function to a flat goto-CFG — the
first attempt did collapse it and cost 162 gotos where 0 were needed.

`0xd0480`: crash -> 162 gotos (collapse) -> 2 gotos (cut) -> 0 gotos (cut + real stack).

### Empty strings, wide literals, table names (`dd4b502`)

- `""` / `L""` were unrepresentable (a lone NUL fails every length filter), so
  kernel32 printed `L""` as the integer `0x904cc` in 17 functions. Accepted now
  only when the preceding bytes prove the address is inside the string pool.
- `try_string_lit` never tried wide strings, so one arm of a ternary could be a
  string and the other a magic number for the same kind of value.
- Static tables had their *shape* recovered but no *name*:
  `((uint8_t*)0x8dcb0)[i]`. Now `((int32_t*)&byte_94310)[a1]`.

Raw addresses in pointer positions 199 -> 37; gotos unchanged.

### Double truncation and dropped SEH handlers (`1a02d90`)

- A renderer branch rewrote `base op <float const>` into a float bit-reinterpret
  without checking whether the base was already floating-point, silently
  narrowing double arithmetic to single precision.
- An inline `__except` handler is entered by the OS unwinder, so no `goto`
  targets it — the dead-code pass deleted the whole handler body. kernel32's
  `s_AslpFileGetCrcChecksum` lost its entire error path.

---

## Standing constraints

- **Never freeze.** Every function is time- and work-bounded; the structurer is
  additionally depth-bounded. No input may hang or crash the process.
- **Never trade structure for speed.** Goto count is a quality metric and must
  not regress to make something faster.
- **A wrong name is worse than no name.** Prefer `fun_<rva>` over a guess.
- **Parallel output must be byte-identical to serial.** Asserted by
  `crates/shell/tests/throughput.rs` on kernel32 (2590 fns) and ntdll (4598).

## Verifying a change

```bash
DS_REAL_BIN='C:\Windows\System32\kernel32.dll' cargo test --release --test throughput -- --nocapture
```

```bash
DS_REAL_BIN='C:\Windows\System32\kernel32.dll' cargo test --release --test stress -- --nocapture
```

`stress` reports goto count, phantom leaks and the slowest functions;
`throughput` asserts the parallel/serial equality above. For a single function,
`DS_PAIRS_RVAS=0x<rva> cargo test --release --test dump_pairs -- --nocapture`
writes a disassembly/pseudo-C pair into `_qa/out/pairs`.
