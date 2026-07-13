// Comprehensive recovery showcase: namespace + class + RTTI-struct + plain-struct + template.
#include <cstdint>

namespace game {

    // (1) a plain STRUCT, no virtuals -> NO RTTI. Recovered as an inferred `struct` from its
    //     field accesses (synthetic name), never promoted to a class.
    struct Vec3 { float x, y, z; };

    // (2) a CLASS (has virtuals -> RTTI, tag .?AV). -> `class game::Entity`
    class Entity {
    public:
        int      health;   // +8  (vtable ptr at +0)
        int      level;    // +12
        Entity*  target;   // +16
        virtual int  take_damage(int dmg) { health -= dmg; return health; }
        virtual void level_up()           { level++; }
        virtual ~Entity() {}
    };

    // (3) a STRUCT WITH VIRTUALS (RTTI, tag .?AU) -> `struct game::Body` (kept a struct, not class)
    struct Body {
        float mass;
        float drag;
        virtual float momentum() { return mass * drag; }
        virtual ~Body() {}
    };

    // (4) a TEMPLATE. Each instantiation is a concrete RTTI type -> `class game::Pool<int>` etc.
    template<typename T>
    class Pool {
    public:
        T*   data;
        int  count;
        int  capacity;
        virtual T*   alloc() { return &data[count++]; }
        virtual void reset() { count = 0; }
        virtual ~Pool() {}
    };
}

// exports that force each type + its ctor/vtable + field uses into the image
extern "C" __declspec(dllexport) float vec3_len2(game::Vec3* v) {
    return v->x * v->x + v->y * v->y + v->z * v->z;
}
extern "C" __declspec(dllexport) game::Entity* make_entity()          { return new game::Entity(); }
extern "C" __declspec(dllexport) int           hurt(game::Entity* e, int d) { return e->take_damage(d); }
extern "C" __declspec(dllexport) game::Body*   make_body()            { return new game::Body(); }
extern "C" __declspec(dllexport) game::Pool<int>*   make_pool_i()     { return new game::Pool<int>(); }
extern "C" __declspec(dllexport) game::Pool<float>* make_pool_f()     { return new game::Pool<float>(); }
