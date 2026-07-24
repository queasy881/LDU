# Scripting the decompiler

Everything the analysis can do used to require clicking in the GUI, so the tasks
people actually automate — bulk renaming, sweeping every function for a pattern,
applying a recovered struct everywhere, exporting pseudocode — had no path.

`--script` runs the engine headlessly over a **line-oriented JSON stream**, so a
script in any language drives it through a pipe. No interpreter is embedded and
no build dependency is added.

```bash
disasmstudio --script <binary> commands.jsonl     # or - for stdin
```

One JSON object per line in, one per line out, in order. A failing command
answers `{"ok":false,"error":...}` and the stream **continues**, so one bad rva in
a 10k-function sweep does not discard the run. Blank lines and `#` comments are
ignored. `rva` accepts `"0x1000"`, `"1000"` (hex) or a JSON number.

| command | result |
|---|---|
| `{"cmd":"meta"}` | arch, base, entry, counts |
| `{"cmd":"functions","limit":N,"offset":N}` | `[{rva,name,size,blocks,calls}]` |
| `{"cmd":"decompile","rva":..}` | `{rva,code}` |
| `{"cmd":"disasm","rva":..,"count":N}` | `[{rva,mnemonic,operands}]` |
| `{"cmd":"xrefs","rva":..}` | `[{from,to,kind}]` |
| `{"cmd":"rename","rva":..,"name":..}` | `{ok}` |
| `{"cmd":"comment","rva":..,"text":..}` | `{ok}` |
| `{"cmd":"set_var_type","rva":..,"var":"a1","type":"struct Foo*"}` | `{ok}` |
| `{"cmd":"save_annotations","path":..}` / `load_annotations` | `{ok}` |

## Example: retype a parameter and see it applied

```jsonl
{"cmd":"decompile","rva":"0x1008"}
{"cmd":"set_var_type","rva":"0x1008","var":"a1","type":"struct MyThing*"}
{"cmd":"decompile","rva":"0x1008"}
```

```
BEFORE  fun_00001008(struct s_fun_00001008_a1*a1, int64_t a2)
AFTER   fun_00001008(struct MyThing*a1, int64_t a2)
```

Retyping is scoped to one function and re-decompiles only that function
(~3 ms against ~10 s for a 120-function pass), so a sweep that retypes
thousands of variables stays linear in the work you asked for.

## Example: name every function that references a string

```python
import json, subprocess
p = subprocess.Popen(["disasmstudio","--script","target.dll","-"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def call(**kw):
    p.stdin.write(json.dumps(kw) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())

for f in call(cmd="functions")["result"]:
    code = call(cmd="decompile", rva=f["rva"])
    if code["ok"] and "CreateFileW" in code["result"]["code"]:
        call(cmd="rename", rva=f["rva"], name=f"opens_file_{f['rva']:x}")
call(cmd="save_annotations", path="target.dsanno.json")
```
