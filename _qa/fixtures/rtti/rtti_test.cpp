/* rtti_test.cpp - RTTI-recovery testbed for the DisasmStudio decompiler.
 *
 * Self-contained (no external deps, no iostream/STL). Defines a 3-class
 * polymorphic hierarchy (Shape base + Circle/Rectangle derived, Square a
 * second-level derived) so the compiler emits, for each polymorphic class:
 *   - a vtable                 ??_7<class>@@6B@
 *   - an RTTI type descriptor  ??_R0?AV<class>@@@8   (embeds ".?AV<class>@@")
 *   - a complete-object-locator ??_R4<class>@@6B@ and the class-hierarchy /
 *     base-class-descriptor chain (??_R3/??_R2/??_R1) needed to reconstruct
 *     the inheritance graph.
 *
 * Each exported factory (extern "C" __declspec(dllexport)) news an instance
 * and calls the virtuals through a base pointer, so the vtables are emitted
 * and every virtual slot is reachable. identify_shape() additionally uses
 * dynamic_cast and typeid to force the full RTTI machinery to be referenced.
 *
 * Build (RTTI on = /GR; /GR is the cl default but is passed explicitly so the
 * intent is documented and the flag survives a copied command line):
 *   call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
 *   cl /nologo /LD /GR /Od /W3 rtti_test.cpp
 *
 * Confirm RTTI + vtables landed in the DLL:
 *   dumpbin /SYMBOLS rtti_test.obj | findstr "??_7 ??_R0 ??_R4"
 *   dumpbin /RAWDATA:bytes /SECTION:.rdata rtti_test.dll | findstr ".?AV"
 * Expected: the type-descriptor strings ".?AVShape@@", ".?AVCircle@@",
 * ".?AVRectangle@@", ".?AVSquare@@" and vtable symbols "??_7Shape@@6B@" etc.
 */

#include <typeinfo>   /* compiler-support header for typeid()/type_info::operator== */

/* --- base ------------------------------------------------------------- */
class Shape {
public:
    int   tag;
    Shape(int t) : tag(t) {}
    virtual ~Shape() {}              /* virtual dtor -> deleting-dtor vslot  */
    virtual double area() const = 0; /* pure virtual                        */
    virtual int    sides() const { return 0; }
    virtual int    kind()  const { return 0; }
};

/* --- first-level derived ---------------------------------------------- */
class Circle : public Shape {
public:
    double r;
    Circle(double radius) : Shape(1), r(radius) {}
    ~Circle() {}
    double area()  const { return 3.14159265358979 * r * r; }
    int    sides() const { return 0; }
    int    kind()  const { return 1; }
};

class Rectangle : public Shape {
public:
    double w, h;
    Rectangle(double width, double height) : Shape(2), w(width), h(height) {}
    ~Rectangle() {}
    double area()  const { return w * h; }
    int    sides() const { return 4; }
    int    kind()  const { return 2; }
};

/* --- second-level derived (exercises multi-level base-class descriptors) */
class Square : public Rectangle {
public:
    Square(double side) : Rectangle(side, side) {}
    ~Square() {}
    int kind() const { return 3; }
};

/* Round the virtual double result to an int so the exports are ABI-simple
 * (return in eax, easy to eyeball in decompiled output). */
static int iround(double d) { return (int)(d + 0.5); }

/* --- exported factories ---------------------------------------------- */
extern "C" __declspec(dllexport) int make_circle(double radius) {
    Shape* s = new Circle(radius);
    int a = iround(s->area()) + s->sides() + s->kind();
    delete s;                        /* virtual dtor through base ptr */
    return a;
}

extern "C" __declspec(dllexport) int make_rectangle(double w, double h) {
    Shape* s = new Rectangle(w, h);
    int a = iround(s->area()) + s->sides() + s->kind();
    delete s;
    return a;
}

extern "C" __declspec(dllexport) int make_square(double side) {
    Shape* s = new Square(side);
    int a = iround(s->area()) + s->sides() + s->kind();
    delete s;
    return a;
}

/* selector: 0=Circle 1=Rectangle 2=Square. Uses typeid + dynamic_cast to
 * force the RTTI descriptors to be *referenced* (not just emitted), which
 * guarantees the .?AV type-descriptor strings survive into .rdata. */
extern "C" __declspec(dllexport) int identify_shape(int selector, double x) {
    Shape* s;
    if (selector == 0)      s = new Circle(x);
    else if (selector == 1) s = new Rectangle(x, x);
    else                    s = new Square(x);

    int result = s->kind() * 1000 + iround(s->area());

    /* dynamic_cast down-cast: emits __RTDynamicCast + references the RTTI
     * class-hierarchy descriptors for Rectangle/Square. */
    Rectangle* rc = dynamic_cast<Rectangle*>(s);
    if (rc) result += 100 + rc->sides();

    /* typeid: references the type descriptor (??_R0) directly. */
    if (typeid(*s) == typeid(Square)) result += 10;

    delete s;
    return result;
}
