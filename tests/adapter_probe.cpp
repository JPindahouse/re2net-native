// R1328 adapter probe: the actual ReEngineBridge implementation against a FAKE C API
// Uses a fake checked C API. No loader, SDK
// runtime, engine, network or DLL call happens. Re-runs the review's four counterexamples
// (which must now be refused) plus the new fail-closed edges.
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
extern "C" {
#include "reframework/API.h"
}
#include "re2net/core/engine_bridge.hpp"
#define private public
#include "re_engine_bridge.hpp"
#undef private
#include "re_engine_bridge.cpp"

using namespace re2net::adapter;
using namespace re2net::core;

namespace {
int g_fail = 0, g_checks = 0;
#define CHECK(c) do { ++g_checks; if (!(c)) { ++g_fail; std::printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

template <class T> T h(uintptr_t n) { return reinterpret_cast<T>(n); }
struct Obj { const char* name; };
struct Array { std::vector<void*> entries; };
struct Work { float value = 0, speed = 0; int32_t side = 0; void* layer = nullptr; };

Obj p1{"Leon"};
std::vector<Obj> doors(400), actors(40);
Array door_array, actor_array, work_array;
Work work_a{0.25f, 0, 0, nullptr}, work_b{0.75f, 0, 1, nullptr}, work_a2{0.5f, 0, 0, nullptr};
void* work_array_slot = &work_array;
uintptr_t g_scene = 900;
int item_calls = 0;
std::function<void()> during_open;
ReEngineBridge* g_bridge = nullptr;
re2net::core::ObjRef g_door_ref{}, g_actor_ref{};
InvokeResult g_nested{};

constexpr uintptr_t SCENE = 1, FIND = 2, COUNT = 3, ITEM = 4, COMPGO = 5, NAME = 6, EQUALS = 7, P1 = 8, TRANS = 9, POS = 10,
                    OPEN = 11, SETVALUE = 12;
int g_addref = 0, g_release = 0, g_setvalue = 0, g_open_entries = 0;
bool g_setvalue_fails = false;
bool g_live = true;                       // the plugin's live local connection/operation (hook permit)
bool g_permit = true;                     // the core's permit_now() for a mutation
std::function<void()> g_on_item, g_on_setvalue, g_on_pos, g_on_scene;   // callbacks inside the fake engine calls
const Permit allow = [] { return g_permit; };
re2net::core::ObjRef g_permit_door{}, g_permit_actor{};   // the refs the hook last asked the permit about
int g_permit_calls = 0;

REFrameworkResult call(REFrameworkMethodHandle mh, void* object, void** args, unsigned int, void* out, unsigned int size) {
    if (size < 129) return REFRAMEWORK_ERROR_OUT_TOO_SMALL;
    std::memset(out, 0, size);
    auto ptr = [&](void* x) { std::memcpy(out, &x, sizeof x); };
    auto m = reinterpret_cast<uintptr_t>(mh);
    if (m == SCENE) { if (g_on_scene) g_on_scene(); ptr(h<void*>(g_scene)); }
    else if (m == FIND) ptr(args[0] == h<void*>(101) ? static_cast<void*>(&door_array) : static_cast<void*>(&actor_array));
    else if (m == COUNT) { auto n = static_cast<int32_t>(static_cast<Array*>(object)->entries.size()); std::memcpy(out, &n, 4); }
    else if (m == ITEM) {
        ++item_calls;
        if (g_on_item) g_on_item();
        auto* a = static_cast<Array*>(object);
        auto i = reinterpret_cast<intptr_t>(args[0]);
        ptr(i >= 0 && static_cast<size_t>(i) < a->entries.size() ? a->entries[i] : nullptr);
    }
    else if (m == COMPGO || m == TRANS) ptr(object);
    else if (m == NAME) ptr(const_cast<char*>(static_cast<Obj*>(object)->name));
    else if (m == EQUALS) { bool b = std::strcmp(static_cast<const char*>(object), static_cast<const char*>(args[0])) == 0; std::memcpy(out, &b, 1); }
    else if (m == P1) ptr(&p1);
    else if (m == POS) { if (g_on_pos) g_on_pos(); float xyzw[4] = {1, 2, 3, 0}; std::memcpy(out, xyzw, 16); }
    else if (m == OPEN) {
        ++g_open_entries;
        if (during_open) during_open();
        bool result = true;
        std::memcpy(out, &result, 1);
    }
    else if (m == SETVALUE) {   // System.Array.SetValue(System.Object value, System.Int32 index)
        ++g_setvalue;
        if (g_on_setvalue) g_on_setvalue();
        if (g_setvalue_fails) return REFRAMEWORK_ERROR_EXCEPTION;
        auto* a = static_cast<Array*>(object);
        auto i = reinterpret_cast<intptr_t>(args[1]);
        if (i >= 0 && static_cast<size_t>(i) < a->entries.size()) a->entries[i] = args[0];
    }
    else return REFRAMEWORK_ERROR_UNKNOWN;
    return REFRAMEWORK_ERROR_NONE;
}

void hook(int argc, void* receiver) {   // what REFramework's pre-hook would pass: [vm ctx, this]
    void* argv[2] = {h<void*>(0x77), receiver};
    ReEngineBridge::on_opened_witnessed(argc, argv);
}
void hook_scope_enter(void* door) {
    void* argv[2] = {h<void*>(0x77), door};
    ReEngineBridge::on_door_scope_enter(2, argv);
}

void layout(int n_doors, std::initializer_list<int> door_at, int n_actors, std::initializer_list<int> hunk_at, int nonnull_doors = -1) {
    door_array.entries.clear();
    actor_array.entries.clear();
    for (int i = 0; i < n_doors; ++i) {
        doors[i].name = "other";
        door_array.entries.push_back(nonnull_doors >= 0 && i >= nonnull_doors ? nullptr : &doors[i]);
    }
    for (int i : door_at) { doors[i].name = "door"; door_array.entries[i] = &doors[i]; }
    for (int i = 0; i < n_actors; ++i) { actors[i].name = "other"; actor_array.entries.push_back(&actors[i]); }
    for (int i : hunk_at) actors[i].name = "pl4000";
}
}  // namespace

int main() {
    REFrameworkSDKFunctions functions{};
    functions.get_native_singleton = [](const char*) -> void* { return h<void*>(901); };
    functions.get_managed_singleton = [](const char*) { return h<REFrameworkManagedObjectHandle>(902); };
    functions.typeof_ = [](const char* n) { return h<REFrameworkManagedObjectHandle>(std::strcmp(n, "door") == 0 ? 101 : 102); };
    functions.create_managed_string_normal = [](const char* s) { return reinterpret_cast<REFrameworkManagedObjectHandle>(const_cast<char*>(s)); };
    REFrameworkTDBTypeDefinition types{};
    types.get_full_name = [](REFrameworkTypeDefinitionHandle t, char* out, unsigned int n, unsigned int* len) {
        const char* s = t == h<REFrameworkTypeDefinitionHandle>(101) ? "door" : "actor";
        if (n < std::strlen(s) + 1) return REFRAMEWORK_ERROR_OUT_TOO_SMALL;
        std::memcpy(out, s, std::strlen(s) + 1);
        if (len) *len = static_cast<unsigned int>(std::strlen(s));
        return REFRAMEWORK_ERROR_NONE;
    };
    REFrameworkTDBMethod methods{};
    methods.invoke = &call;
    REFrameworkManagedObject managed{};
    managed.add_ref = [](REFrameworkManagedObjectHandle) { ++g_addref; };
    managed.release = [](REFrameworkManagedObjectHandle) { ++g_release; };
    REFrameworkTDBField fields{};
    fields.get_data_raw = [](REFrameworkFieldHandle f, void* object, bool) -> void* {
        auto id = reinterpret_cast<uintptr_t>(f);
        if (id == 3) return &work_array_slot;
        auto* w = static_cast<Work*>(object);
        if (id == 4) return &w->value;
        if (id == 5) return &w->speed;
        if (id == 6) return &w->side;
        if (id == 7) return &w->layer;
        return nullptr;
    };
    REFrameworkSDKData sdk{};
    sdk.functions = &functions;
    sdk.type_definition = &types;
    sdk.method = &methods;
    sdk.managed_object = &managed;
    sdk.field = &fields;

    ReEngineBridge bridge;
    g_bridge = &bridge;
    bridge.sdk_ = &sdk;
    bridge.ok_ = true;
    bridge.witness_ok_ = true;
    bridge.build_gate_ok_ = true;
    g_owner.store(&bridge);                                       // what preflight publishes
    ReEngineBridge::set_engine_thread(std::this_thread::get_id()); // what the plugin's first callback publishes
    bridge.hook_permit_ = [](ObjRef door, ObjRef actor) {           // stands in for retained_hook_permit (blocked + core.lease_permit)
        ++g_permit_calls;
        g_permit_door = door;
        g_permit_actor = actor;
        return g_live;
    };
    auto& r = bridge.r_;
    r.door = h<REFrameworkTypeDefinitionHandle>(101);
    r.player_condition = h<REFrameworkTypeDefinitionHandle>(102);
    r.mgr_current_scene = h<REFrameworkMethodHandle>(SCENE);
    r.scene_find_components = h<REFrameworkMethodHandle>(FIND);
    r.array_count = h<REFrameworkMethodHandle>(COUNT);
    r.array_item = h<REFrameworkMethodHandle>(ITEM);
    r.comp_game_object = h<REFrameworkMethodHandle>(COMPGO);
    r.go_name = h<REFrameworkMethodHandle>(NAME);
    r.string_equals = h<REFrameworkMethodHandle>(EQUALS);
    r.pm_current_player = h<REFrameworkMethodHandle>(P1);
    r.go_transform = h<REFrameworkMethodHandle>(TRANS);
    r.tr_position = h<REFrameworkMethodHandle>(POS);
    r.door_request_from_npc = h<REFrameworkMethodHandle>(OPEN);
    r.door_peeked_work = h<REFrameworkFieldHandle>(3);
    r.pw_value = h<REFrameworkFieldHandle>(4);
    r.pw_speed = h<REFrameworkFieldHandle>(5);
    r.pw_side = h<REFrameworkFieldHandle>(6);
    r.pw_motion_layer = h<REFrameworkFieldHandle>(7);
    DoorKey key{"door", 23, 347};

    // Review counterexample 3: duplicates hidden beyond the enumeration bound.
    layout(257, {0, 256}, 17, {0, 16});
    auto d = bridge.resolve_door(key);
    auto a = bridge.resolve_actor(ActorRole::P2);
    int dup_door_found = d.status == LookupStatus::Found, dup_actor_found = a.status == LookupStatus::Found;
    CHECK(d.status == LookupStatus::Unsupported);
    CHECK(a.status == LookupStatus::Unsupported);
    // Within the bound a duplicate is a duplicate, never Found.
    layout(201, {0, 200}, 16, {0, 15});
    CHECK(bridge.resolve_door(key).status == LookupStatus::Duplicate);
    CHECK(bridge.resolve_actor(ActorRole::P2).status != LookupStatus::Found);
    // Nulls count toward the bound: 300 slots with one door is still an overflow, with no 300 item calls.
    layout(300, {0}, 1, {0}, /*nonnull_doors=*/1);
    item_calls = 0;
    CHECK(bridge.resolve_door(key).status == LookupStatus::Unsupported && item_calls == 0);
    // Unique within the bound: Found, with an adapter serial (not the address) as incarnation.
    layout(10, {3}, 4, {2});
    d = bridge.resolve_door(key);
    a = bridge.resolve_actor(ActorRole::P2);
    CHECK(d.status == LookupStatus::Found && a.status == LookupStatus::Found);
    CHECK(d.ref.incarnation != reinterpret_cast<uint64_t>(&doors[3]));
    CHECK(bridge.still_valid(d.ref) && bridge.still_valid(a.ref));

    // Review counterexample 2: an unrelated door's onOpened attributed to the target.
    during_open = [] { hook(2, &doors[7]); };
    auto inv = bridge.open_by_actor(d.ref, a.ref, allow);
    int unrelated_attributed = inv.on_opened == Tri::True;
    CHECK(inv.status == InvokeStatus::ReturnedTrue && inv.on_opened == Tri::False);
    during_open = [] { hook(2, &doors[7]); hook(2, &doors[3]); };   // the target's own event counts
    CHECK(bridge.open_by_actor(d.ref, a.ref, allow).on_opened == Tri::True);
    during_open = [] { hook(1, nullptr); };                          // unattributable layout: Unknown, never True
    CHECK(bridge.open_by_actor(d.ref, a.ref, allow).on_opened == Tri::Unknown);
    during_open = nullptr;
    hook(2, &doors[3]);                                              // outside any invocation: ignored
    CHECK(bridge.open_by_actor(d.ref, a.ref, allow).on_opened == Tri::False);
    // Reentrant mutation from inside the engine call is refused without an engine call.
    g_door_ref = d.ref;
    g_actor_ref = a.ref;
    during_open = [] { g_nested = g_bridge->open_by_actor(g_door_ref, g_actor_ref, allow); };
    bridge.open_by_actor(d.ref, a.ref, allow);
    CHECK(g_nested.status == InvokeStatus::NestedRefused);
    during_open = nullptr;

    // Review counterexample 4: side-B work returned for side A.
    std::optional<float> speed;
    Tri layer = Tri::Unknown;
    work_array.entries = {&work_b, nullptr};
    auto v = bridge.peeked_value(&doors[3], Side::A, &speed, &layer);
    int wrong_side = v && *v == 0.75f;
    CHECK(!v);
    work_array.entries = {&work_b, &work_a};
    v = bridge.peeked_value(&doors[3], Side::A, &speed, &layer);
    CHECK(v && *v == 0.25f);
    CHECK(!bridge.peeked_value(&doors[3], Side::Unknown, &speed, &layer));
    work_array.entries = {&work_a, &work_a2};                        // two works claim side A: ambiguous
    CHECK(!bridge.peeked_value(&doors[3], Side::A, &speed, &layer));

    // Incarnation: same address in a different scene object, or a stale serial, is not valid.
    CHECK(!bridge.still_valid(ObjRef{d.ref.token, d.ref.incarnation + 1}));
    g_scene = 950;
    CHECK(!bridge.still_valid(d.ref) && bridge.open_by_actor(d.ref, a.ref, allow).status == InvokeStatus::Stale);
    g_scene = 900;

    // Exact-build gate: without it nothing resolves or mutates.
    bridge.build_gate_ok_ = false;
    CHECK(!bridge.caps().build_ok && !bridge.caps().actor_open_ok);
    CHECK(bridge.resolve_door(key).status == LookupStatus::Unsupported);
    CHECK(bridge.open_by_actor(d.ref, a.ref, allow).status == InvokeStatus::Unsupported);
    bridge.build_gate_ok_ = true;

    // ---------------------------------------------------------------- R1356 eligibility lease
    layout(10, {3}, 4, {2});
    d = bridge.resolve_door(key);
    a = bridge.resolve_actor(ActorRole::P2);
    void* hunk = &actors[2];
    Obj npc_a{"npcA"}, npc_b{"npcB"};
    Array cand;
    void* ret = &cand;
    auto build = [&](void* s0, void* s1, void* s2) { cand.entries = {s0, s1, s2}; };
    auto door_update = [&](void* door) {   // what the hooks see for one door's updatePeeked + collect
        hook_scope_enter(door);
        ReEngineBridge::on_candidates_built(&ret);
        ReEngineBridge::on_door_scope_exit();
    };
    r.array_set_value = h<REFrameworkMethodHandle>(SETVALUE);
    // Without the hooks/metadata no lease is granted at all.
    CHECK(!bridge.lease_eligibility(d.ref, a.ref) && !bridge.caps().eligibility_ok);
    bridge.eligibility_meta_ok_ = true;
    bridge.eligibility_hooks_ok_ = true;
    g_owner = &bridge;
    CHECK(bridge.caps().eligibility_ok);
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);                                     // no lease yet: untouched
    CHECK(cand.entries[1] == nullptr && g_setvalue == 0);
    CHECK(!bridge.lease_eligibility(a.ref, a.ref));             // wrong token kinds: refused
    CHECK(bridge.lease_eligibility(d.ref, a.ref) && g_addref == 1);
    CHECK(bridge.lease_eligibility(d.ref, a.ref) && g_addref == 1);   // renewal of the same pair: no second ref
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    CHECK(cand.entries[0] == &p1 && cand.entries[1] == hunk && cand.entries[2] == nullptr);
    build(&p1, &npc_a, nullptr);                                // a real NPC keeps its slot
    door_update(&doors[3]);
    CHECK(cand.entries[1] == &npc_a && cand.entries[2] == hunk);
    build(&p1, &npc_a, &npc_b);                                 // no empty slot: nothing replaced
    door_update(&doors[3]);
    CHECK(cand.entries[1] == &npc_a && cand.entries[2] == &npc_b);
    build(hunk, nullptr, nullptr);                              // partner already the CurrentPlayer
    door_update(&doors[3]);
    CHECK(cand.entries[1] == nullptr);
    build(&p1, nullptr, nullptr);
    door_update(&doors[7]);                                     // another door's update: untouched
    ReEngineBridge::on_candidates_built(&ret);                  // a list built outside any door scope: untouched
    CHECK(cand.entries[1] == nullptr);
    hook_scope_enter(&doors[3]);                                // nested: another door inside the leased one
    hook_scope_enter(&doors[7]);
    ReEngineBridge::on_candidates_built(&ret);
    CHECK(cand.entries[1] == nullptr);
    ReEngineBridge::on_door_scope_exit();
    ReEngineBridge::on_candidates_built(&ret);
    CHECK(cand.entries[1] == hunk);
    ReEngineBridge::on_door_scope_exit();
    build(&p1, nullptr, nullptr);
    std::thread other([&] { door_update(&doors[3]); });        // the right door on another thread: untouched
    other.join();
    CHECK(cand.entries[1] == nullptr);
    hook_scope_enter(&doors[3]);                                // a post hook that never ran...
    ReEngineBridge::begin_frame();                              // ...is reset and counted at the next frame
    ReEngineBridge::on_candidates_built(&ret);
    CHECK(cand.entries[1] == nullptr && bridge.eligibility().unbalanced == 1);
    cand.entries = {&p1, nullptr};                              // not the exact-build 3-element shape
    door_update(&doors[3]);
    CHECK(cand.entries[1] == nullptr);
    build(&p1, nullptr, nullptr);
    g_setvalue_fails = true;                                    // managed setter failure: refused, not assumed
    door_update(&doors[3]);
    g_setvalue_fails = false;
    CHECK(cand.entries[1] == nullptr);
    auto rep = bridge.eligibility();
    CHECK(rep.active && rep.injected == 3 && rep.no_free_slot == 1 && rep.already_member == 1 && rep.refused == 2);
    bridge.release_eligibility();
    CHECK(g_release == 1 && !bridge.eligibility().active);
    bridge.release_eligibility();                               // idempotent
    CHECK(g_release == 1);
    door_update(&doors[3]);                                     // released: untouched
    CHECK(cand.entries[1] == nullptr);
    g_scene = 951;                                              // stale scene: no lease
    CHECK(!bridge.lease_eligibility(d.ref, a.ref) && g_addref == 1);
    g_scene = 900;
    bridge.build_gate_ok_ = false;
    CHECK(!bridge.lease_eligibility(d.ref, a.ref) && !bridge.caps().eligibility_ok);
    bridge.build_gate_ok_ = true;

    // ---------------------------------------------------------------- R1414 static review fixtures
    // Finding 1: authority lost DURING the adapter's final reads (position) -> PermitDenied,
    // requestOpenFromNPC never entered.
    d = bridge.resolve_door(key);
    a = bridge.resolve_actor(ActorRole::P2);
    int entries0 = g_open_entries;
    g_on_pos = [] { g_permit = false; };
    auto denied = bridge.open_by_actor(d.ref, a.ref, allow);
    g_on_pos = nullptr;
    g_permit = true;
    CHECK(denied.status == InvokeStatus::PermitDenied && g_open_entries == entries0);
    CHECK(bridge.open_by_actor(d.ref, a.ref, Permit{}).status == InvokeStatus::PermitDenied);   // no permit = refusal
    CHECK(bridge.open_by_actor(d.ref, a.ref, allow).status == InvokeStatus::ReturnedTrue && g_open_entries == entries0 + 1);

    // Finding 2: the local connection died between pump callbacks; the retained lease must
    // not write, and the hook releases it.
    auto relet = [&] { CHECK(bridge.lease_eligibility(d.ref, a.ref)); };
    relet();
    int sets0 = g_setvalue, rel0 = g_release;
    g_live = false;
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    g_live = true;
    CHECK(cand.entries[1] == nullptr && g_setvalue == sets0 && !bridge.eligibility().active && g_release == rel0 + 1);
    CHECK(bridge.eligibility().revoked_in_hook == 1);
    // ... the native scene object changed between callbacks
    relet();
    g_scene = 952;
    door_update(&doors[3]);
    g_scene = 900;
    CHECK(cand.entries[1] == nullptr && g_setvalue == sets0 && !bridge.eligibility().active);
    // ... the partner no longer resolves to the leased object
    relet();
    actors[2].name = "other";
    door_update(&doors[3]);
    actors[2].name = "pl4000";
    CHECK(cand.entries[1] == nullptr && g_setvalue == sets0 && !bridge.eligibility().active);
    // ... authority lost DURING the managed array reads: the final fence before the setter refuses
    d = bridge.resolve_door(key);
    a = bridge.resolve_actor(ActorRole::P2);
    relet();
    g_on_item = [] { g_live = false; };
    door_update(&doors[3]);
    g_on_item = nullptr;
    g_live = true;
    CHECK(cand.entries[1] == nullptr && g_setvalue == sets0 && !bridge.eligibility().active);

    // Finding 3: a re-entrant collect of the same leased door during the setter is refused
    // (guard held across the callbacks); the outer injection completes once.
    relet();
    int inj0 = static_cast<int>(bridge.eligibility().injected);
    Array inner;
    void* inner_ret = &inner;
    bool reentered = false;
    g_on_setvalue = [&] {
        if (reentered) return;   // one nested attempt (never reassign this function from inside itself)
        reentered = true;
        inner.entries = {&p1, nullptr, nullptr};
        hook_scope_enter(&doors[3]);
        ReEngineBridge::on_candidates_built(&inner_ret);
        ReEngineBridge::on_door_scope_exit();
    };
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    g_on_setvalue = nullptr;
    CHECK(cand.entries[1] == hunk && inner.entries[1] == nullptr);
    CHECK(bridge.eligibility().reentry_refused == 1 && static_cast<int>(bridge.eligibility().injected) == inj0 + 1);
    // ... a C++ exception inside a hook callback is contained (no propagation), counted, and
    // the lease is released: no later write on that authority.
    g_on_item = [] { throw std::runtime_error("model callback exception"); };
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    g_on_item = nullptr;
    CHECK(bridge.eligibility().hook_faults == 1 && !bridge.eligibility().active && cand.entries[1] == nullptr);
    CHECK(!bridge.in_engine_call_);   // the scoped guard was restored through the unwind

    // Finding 4: before/without the engine-owner identity, hooks read no lease/report state
    // and leases/mutations are refused (sequential evidence only; not a concurrency proof).
    relet();
    auto report0 = bridge.eligibility();
    std::thread::id elsewhere;
    {
        std::thread t([&] { elsewhere = std::this_thread::get_id(); });
        t.join();
    }
    ReEngineBridge::set_engine_thread(elsewhere);   // this thread is no longer the owner
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    ReEngineBridge::begin_frame();
    CHECK(cand.entries[1] == nullptr && g_setvalue == sets0 + 1);
    CHECK(bridge.open_by_actor(d.ref, a.ref, allow).status == InvokeStatus::Unsupported);
    ReEngineBridge::set_engine_thread(std::this_thread::get_id());
    auto report1 = bridge.eligibility();
    CHECK(report1.scopes == report0.scopes && report1.injected == report0.injected && report1.active);

    // ---------------------------------------------------------------- R1446 static review fixtures
    // Finding 1 (the review's schedule): authority lost DURING the last current_scene getter,
    // which still returns the same bound scene. The pure permit AFTER every managed read
    // refuses; SetValue is never entered.
    d = bridge.resolve_door(key);
    a = bridge.resolve_actor(ActorRole::P2);
    relet();
    const int sets1 = g_setvalue;
    g_on_scene = [] { g_live = false; };
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    g_on_scene = nullptr;
    g_live = true;
    CHECK(cand.entries[1] == nullptr && g_setvalue == sets1 && !bridge.eligibility().active);
    // ... the lease released by a callback inside that getter: no write on a stale lease
    relet();
    g_on_scene = [] { g_bridge->release_eligibility(); };
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    g_on_scene = nullptr;
    CHECK(cand.entries[1] == nullptr && g_setvalue == sets1 && !bridge.eligibility().active);
    // Finding 2: the selected P2 is replaced inside the array reads (same scene; the cached
    // binding and lease still name the old actor). The post-array identity re-check refuses.
    relet();
    const uint32_t revoked1 = bridge.eligibility().revoked_in_hook;
    bool swapped = false;
    g_on_item = [&swapped] {
        if (swapped) return;
        swapped = true;
        actors[2].name = "other";
        actors[3].name = "pl4000";
    };
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    g_on_item = nullptr;
    actors[2].name = "pl4000";
    actors[3].name = "other";
    CHECK(swapped && cand.entries[1] == nullptr && g_setvalue == sets1 && !bridge.eligibility().active);
    CHECK(bridge.eligibility().revoked_in_hook == revoked1 + 1);
    // Pass case: the permit is asked about exactly the leased refs, at entry and at the
    // final fence, and the injection completes once.
    relet();
    g_permit_calls = 0;
    build(&p1, nullptr, nullptr);
    door_update(&doors[3]);
    CHECK(cand.entries[1] == hunk && g_setvalue == sets1 + 1 && g_permit_calls == 2);
    CHECK(g_permit_door == d.ref && g_permit_actor == a.ref);
    // Finding 4: direct lease API calls off the owner thread are refused before any lease
    // state is read: the owner's lease stays held, no managed add_ref/release on that thread.
    const int add1 = g_addref, rel1 = g_release;
    bool off_lease = true;
    EligibilityReport off_report{};
    off_report.active = true;
    {
        std::thread t([&] {
            off_lease = bridge.lease_eligibility(d.ref, a.ref);
            bridge.release_eligibility();
            off_report = bridge.eligibility();
        });
        t.join();
    }
    auto rep2 = bridge.eligibility();
    CHECK(!off_lease && !off_report.active && off_report.injected == 0);
    CHECK(rep2.active && g_addref == add1 && g_release == rel1 && rep2.foreign_thread_refused == 2);

    std::printf("{\"review_counterexamples_reproduced_now\":{\"duplicate_door_beyond_256_reported_found\":%d,"
                "\"duplicate_actor_beyond_16_reported_found\":%d,\"unrelated_onopened_attributed_to_target\":%d,"
                "\"side_B_value_returned_for_side_A\":%d},\"checks\":%d,\"failures\":%d,\"engine_calls\":0}\n",
                dup_door_found, dup_actor_found, unrelated_attributed, wrong_side, g_checks, g_fail);
    return g_fail == 0 && !dup_door_found && !dup_actor_found && !unrelated_attributed && !wrong_side ? 0 : 1;
}
