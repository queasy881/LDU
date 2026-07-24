# Working notes

Running log of what is being worked on, what was just fixed, and what is known
to still be broken. Newest first. This is a status file, not documentation —
the reasoning behind each change lives in its commit message.

---

## Open: Rust goto density

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

### Rust `&str` printed the WRONG string literal

Rust's `&str` is a `(pointer, length)` pair and its literals are packed into
`.rdata` back-to-back **with no NUL terminators**, so the C read-to-the-next-NUL
ran off the end of the intended literal into its neighbours — a confident, wrong
answer. `<bool as Display>::fmt` was the cleanest case:

```c
return core__fmt__Formatter__pad(a2, "falsetrue", 5, a4);   // meant "false"
```

The length was sitting in the very next argument the whole time.

**The diagnosis above was in the wrong place.** The note assumed `read_cstring`
was over-reading at *render* time, which would have made the fix local to
`try_string_lit`. It is not: `lea reg,[rip+str]` turns the address into a literal
at **lift** time (`10_operator_new.inc`, the `DS_NO_LEASTR` path), so by the time
the call arguments are assembled the node is already an `EK::Str` holding the
over-read text and the source address is gone. Rendering could no longer see
*where* the bytes came from, which is why the pair rule alone did nothing.

So `mkText` now records the address it read from, and the call-argument renderer
re-reads that address with the authoritative length. Three pieces:

- `is_rust_image()` (`decompiler.cpp`, cached per engine beside `get_pe_tables`)
- `read_rust_str(rva, len)` (`01_naming_reads.inc`) — length-terminated, no
  MINLEN, an interior NUL rejects the run
- `try_rust_str_slice()` (`16_globals_phis.inc`) — takes `args[i+1]` as the
  length; accepts the pointer as either a bare `Const` or an already-built `Str`
  carrying its source rva

The marker is `/rustc/` OR `library\core\src\` OR `library\std\src\` — panic
`Location` payloads that live in `.rdata`, are referenced by code rather than
being debug info, and survive a fully stripped build (this project's own exe has
`NumberOfSymbols=0` and still carries 84). `RUST_BACKTRACE` was measured and
**rejected**: it is absent from dylib-std builds (rustdoc, rustfmt).

A false positive is the only dangerous direction, since it would change C output.
A sweep of **10,644 binaries / 9.97 GiB** (all of System32 + SysWOW64, Git, LLVM,
three Pythons, CMake, MinGW) found **zero** — every `/rustc/` hit was an
independently-confirmable Rust image (Microsoft's Rust `sudo.exe`, the `_rs`
kernel component, ~20 Rust `.pyd` extensions). A false negative is harmless: it
is exactly the old behaviour.

Result on `disasmstudio.exe` (1200 fns): 158 functions changed, literals ≥40
chars 552 -> 409, leaked `cargo\registry` paths 130 -> 81. The serde
deserializer's nine sites all read correctly now (`"true"`, `"false"`, `"null"`,
`"["`, `"{"`, `",\n"`).

Proof that C is untouched — output **byte-identical** with the fix on and off:
kernel32 701 fns, ntdll 601 fns, a Go binary 251 fns. `throughput` on kernel32
still asserts parallel == serial across 2590 fns (228 fns/s, 5.7x); `stress`
reports 0 phantom leaks. Gated `DS_NO_RUSTSTR`.

**Residual, deliberately not fixed.** Only a call argument has a length sitting
next to it. A `&str` pointer reaching a non-call position (a struct store, a
return value) still over-reads — that is most of the 409 literals that remain.
One site also renders `"fals"` (ptr to `"false"`, length 4): the pair itself was
mis-recovered upstream, so the rule faithfully prints what it was given. Both are
narrower and less wrong than what they replaced, but neither is *right*.

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
