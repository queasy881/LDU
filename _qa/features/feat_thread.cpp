/* FEATURE FIXTURE: thread/sync + class hierarchy recovery.
 * Build: cl /nologo /O2 /EHsc /LD /TP feat_thread.cpp
 * extern "C" exports so names are undecorated for the assertions.
 */
#include <windows.h>
#include <stdint.h>
#define API extern "C" __declspec(dllexport)

/* --- #1 CRITICAL_SECTION as a struct field. A 40-byte field passed by & to the CS APIs IS a
 *     CRITICAL_SECTION; the guarded Enter..Leave region is a locked section. */
typedef struct {
    int32_t counter;
    CRITICAL_SECTION lock;      /* offset 8: recover as CRITICAL_SECTION */
    int32_t total;
} Guarded;

API void th_init(Guarded* g) { InitializeCriticalSection(&g->lock); }
API void th_add(Guarded* g, int v) {
    EnterCriticalSection(&g->lock);
    g->counter += v;
    g->total += v * 2;
    LeaveCriticalSection(&g->lock);
}

/* --- #3/#4 TEB / TLS. A __declspec(thread) global expands to _tls_index + gs:[0x58]. */
__declspec(thread) int t_slot = 0;
API int th_tls_get(void) { return t_slot; }
API void th_tls_set(int v) { t_slot = v; }

/* --- thread creation: the handle should type as HANDLE. */
static DWORD WINAPI worker(LPVOID p) { return 0; }
API HANDLE th_spawn(void) { return CreateThread(0, 0, worker, 0, 0, 0); }

/* --- #2 RTTI inheritance. A polymorphic class WITH a base emits a ClassHierarchyDescriptor
 *     whose BaseClassArray lists the bases (name + offset). Recover `struct Derived : Base`. */
struct Base { virtual int who() const { return 1; } int a; };
struct Derived : Base { int who() const override { return 2; } int b; };
API Base* mk_derived(int x, int y) { Derived* d = new Derived(); d->a = x; d->b = y; return d; }
API int who_is(Base* b) { return b->who(); }
