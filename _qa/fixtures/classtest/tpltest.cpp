// Recoverability test: namespaces, templates, class vs struct.
#include <cstdint>

namespace mytools {
    // free function in a namespace (RTTI does NOT cover these; only symbol names do)
    int add(int a, int b) { return a + b; }

    // a CLASS (has virtuals -> gets RTTI). MSVC mangles class as .?AV, struct as .?AU
    class Widget {
    public:
        int   w;
        int   h;
        virtual int  area()  { return w * h; }
        virtual void grow()  { w++; h++; }
        virtual ~Widget() {}
    };

    // a STRUCT with virtuals (RTTI, tagged .?AU = struct)
    struct Gadget {
        float v;
        virtual float val() { return v; }
        virtual ~Gadget() {}
    };

    // a TEMPLATE. Templates don't exist in the binary; each INSTANTIATION is a concrete
    // type. With a virtual, each instantiation gets its own RTTI (.?AV?$Box@H@ = Box<int>).
    template<typename T> class Box {
    public:
        T value;
        virtual T get() { return value; }
        virtual ~Box() {}
    };
}

extern "C" __declspec(dllexport) int use_add(int a, int b) { return mytools::add(a, b); }
extern "C" __declspec(dllexport) mytools::Widget* mk_widget()  { return new mytools::Widget(); }
extern "C" __declspec(dllexport) mytools::Gadget* mk_gadget()  { return new mytools::Gadget(); }
extern "C" __declspec(dllexport) mytools::Box<int>*   mk_box_i() { return new mytools::Box<int>(); }
extern "C" __declspec(dllexport) mytools::Box<float>* mk_box_f() { return new mytools::Box<float>(); }
