// Namespaced polymorphic class -> exercises Itanium nested-name demangle (N<len><ns><len><name>E).
namespace engine {
    class Widget {
    public:
        int  w;
        int  h;
        virtual int area()   { return w * h; }
        virtual void grow()  { w++; h++; }
        virtual ~Widget()    {}
    };
}
extern "C" __declspec(dllexport) engine::Widget* mk_widget() { return new engine::Widget(); }
extern "C" __declspec(dllexport) int widget_area(engine::Widget* x) { return x->area(); }
