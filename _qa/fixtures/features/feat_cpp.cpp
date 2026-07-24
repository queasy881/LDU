/* FEATURE FIXTURE (C++, x64, /O2, /EHsc) — ground truth for the type/class recoveries.
 * Asserted by _qa/features/verify.py.  Build: cl /nologo /O2 /EHsc /LD /TP feat_cpp.cpp
 *
 * extern "C" on the exports so the NAMES are undecorated and the assertions can find the
 * functions by name. (That also mirrors the real corpus: every DLL here exports undecorated
 * names, which is exactly why the mangled-name sret oracle has zero coverage.)
 */
#include <vector>
#include <string>
#include <new>
#include <stdint.h>
#define API extern "C" __declspec(dllexport)

/* --- RTTI class recovery + vtable slot naming.
 *     A polymorphic class with a ctor emits a COL -> TypeDescriptor; the recovery must name
 *     the class and its vtable slots. */
struct Shape {
    virtual ~Shape() {}
    virtual int area() const { return 0; }
    virtual int perimeter() const { return 0; }
    int w, h;
};
struct Rect : Shape {
    int area() const override { return w * h; }
    int perimeter() const override { return 2 * (w + h); }
};

API Shape* mk_rect(int w, int h) { Rect* r = new Rect(); r->w = w; r->h = h; return r; }
/* virtual dispatch through a param: the devirt target (RTTI-known class -> named method).
 * NB: measured to fire 0 times today — devirt requires the SAME function to construct AND
 * dispatch. This fixture is here so that gap is VISIBLE rather than assumed fixed. */
API int shape_area(Shape* s) { return s->area(); }

/* --- operator new recovery: an alloc-then-vtable-store callee. */
API Shape* mk_shape(void) { return new Shape(); }

/* --- std::vector: _Myfirst/_Mylast/_Myend naming, via the size() subtraction. */
API int vec_size(std::vector<int>& v) { return (int)v.size(); }
/* --- std::vector consumed ONLY as a range: no size() subtraction anywhere, so this is the
 *     begin/end ITERATION signature (the second detector). */
API int vec_range_sum(std::vector<int>& v) {
    int s = 0;
    for (int x : v) s += x;
    return s;
}

/* --- std::string SSO: the _Myres-vs-15 discriminator selects buf vs heap ptr. */
API size_t str_len(std::string& s) { return s.size(); }
API char str_first(std::string& s) { return s.empty() ? '\0' : s[0]; }

/* --- C++ EH: try/catch must be annotated, and the caught TYPE is the open item
 *     (backlog_9 #5: catch(Type&) from the EH typeinfo). */
API int eh_try(int x) {
    try {
        if (x < 0) throw std::bad_alloc();
        return x * 2;
    } catch (std::bad_alloc&) {
        return -1;
    }
}

/* --- self-referential struct -> linked list (backlog_9 #9). A void* field whose LOADED
 *     value is used as a base of the SAME struct is `struct Node* next`. */
struct Node { Node* next; int v; };
API int list_sum(Node* h) {
    int s = 0;
    for (Node* p = h; p; p = p->next) s += p->v;
    return s;
}
