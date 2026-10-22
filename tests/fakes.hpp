// Offline fakes: a scripted EngineBridge, a capturing Transport and Journal, and a
// Link that carries peer messages between a host core and a guest core through the
// strict codec, with controllable loss, duplication, reordering and holding.
#pragma once
#include <algorithm>
#include <deque>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>
#include "re2net/core/door_core.hpp"

namespace re2net::test {
using namespace re2net::core;

class FakeEngine : public EngineBridge {
public:
    // configuration
    EngineCaps caps_value{true, true, true, true, true, true, true, "fake"};
    int door_count = 1;               // 0 missing, 2 duplicate
    bool door_loaded = true;
    Tri locked = Tri::False;
    bool opened = false;
    Side opened_side = Side::Unknown;
    float value = 0.0f;
    float step = 0.12f;               // raw swing units per observed update while moving
    float value_max = 1.0f;           // the fake's own ceiling (real raw units are not assumed 0..1)
    bool moves = true;                // does the leaf actually progress after an open?
    bool follow_driven_only = false;  // guest replica: no local pusher, only follow moves it
    bool sample_readable = true;
    bool post_open_unreadable = false;// every sample after the open is unreadable
    bool motion_layer = true;
    bool p1_present = true, p2_present = true;
    std::optional<float> p1_distance = 5.0f;
    Side actor_side_now = Side::A;
    Side open_side = Side::B;         // side the engine reports opened (host)
    InvokeStatus open_result = InvokeStatus::ReturnedTrue;
    Tri on_opened = Tri::True;        // witness inside the call
    Tri displaced = Tri::False;
    bool follow_works = true;
    std::function<void()> during_open; // runs inside open_* (reentrancy/replacement)
    std::function<void()> in_sample;   // runs inside sample() after the snapshot is taken
    std::function<void()> in_follow;   // runs inside follow() after the write
    std::function<void()> in_final_reads;   // runs inside open_* after its reads, before the permit check
    int permit_denials = 0;
    int throw_sample_at = 0;           // the Nth sample() call throws a C++ exception (0 never)

    // eligibility lease
    bool eligibility_cap = true;      // caps().eligibility_ok
    bool lease_grants = true;         // lease_eligibility() result while refs are valid
    EligibilityReport report{};       // what the engine-side hook "observed" (scripted)
    bool lease_active = false;
    ObjRef lease_door{}, lease_actor{};
    int lease_calls = 0, release_calls = 0;

    // observation
    int open_calls = 0, mirror_calls = 0, follow_calls = 0, sample_calls = 0;
    uint64_t door_inc = 1, p1_inc = 1, p2_inc = 1;

    EngineCaps caps() const override { EngineCaps c = caps_value; c.eligibility_ok = eligibility_cap; return c; }
    bool lease_eligibility(ObjRef d, ObjRef a) override {
        ++lease_calls;
        if (!lease_grants || !still_valid(d) || !still_valid(a)) { lease_active = false; return false; }
        lease_active = true;
        lease_door = d;
        lease_actor = a;
        return true;
    }
    void release_eligibility() noexcept override { ++release_calls; lease_active = false; }
    EligibilityReport eligibility() const override { EligibilityReport r = report; r.active = lease_active; return r; }
    Lookup resolve_door(const DoorKey&) override {
        if (!door_loaded) return {LookupStatus::NotLoaded, {}};
        if (door_count == 0) return {LookupStatus::Missing, {}};
        if (door_count > 1) return {LookupStatus::Duplicate, {}};
        return {LookupStatus::Found, {100, door_inc}};
    }
    Lookup resolve_actor(ActorRole who) override {
        if (who == ActorRole::P1) return p1_present ? Lookup{LookupStatus::Found, {1, p1_inc}} : Lookup{LookupStatus::Missing, {}};
        return p2_present ? Lookup{LookupStatus::Found, {2, p2_inc}} : Lookup{LookupStatus::Missing, {}};
    }
    bool still_valid(ObjRef r) override {
        if (r.token == 100) return r.incarnation == door_inc && door_count == 1 && door_loaded;
        if (r.token == 1) return p1_present && r.incarnation == p1_inc;
        if (r.token == 2) return p2_present && r.incarnation == p2_inc;
        return false;
    }
    std::optional<float> distance(ObjRef, ObjRef) override { return p1_distance; }
    Side actor_side(ObjRef, ObjRef) override { return actor_side_now; }
    // Like the real adapter: own final reads first, then the caller's permit, then entry.
    // open_calls / mirror_calls count ENGINE ENTRIES only (a denied permit is not one).
    InvokeResult open_by_actor(ObjRef d, ObjRef a, const Permit& permit) override {
        if (!still_valid(d) || !still_valid(a)) return {InvokeStatus::Stale};
        if (in_final_reads) in_final_reads();
        if (permit && !permit()) { ++permit_denials; return {InvokeStatus::PermitDenied}; }
        ++open_calls;
        return do_open();
    }
    InvokeResult open_mirror(ObjRef d, ObjRef a, Side s, const Permit& permit) override {
        if (!still_valid(d) || !still_valid(a)) return {InvokeStatus::Stale};
        if (in_final_reads) in_final_reads();
        if (permit && !permit()) { ++permit_denials; return {InvokeStatus::PermitDenied}; }
        ++mirror_calls;
        open_side = s;
        return do_open();
    }
    FollowStatus follow(ObjRef d, float target) override {
        FollowStatus st = do_follow(d, target);
        if (in_follow) in_follow();
        return st;
    }
    DoorSample sample(ObjRef d) override {
        DoorSample s = do_sample(d);
        if (throw_sample_at && sample_calls == throw_sample_at) throw std::runtime_error("fake_sample_exception");
        if (in_sample) in_sample();
        return s;
    }

private:
    FollowStatus do_follow(ObjRef d, float target) {
        ++follow_calls;
        if (!still_valid(d)) return FollowStatus::Stale;
        if (!opened) return FollowStatus::NotOpen;
        if (!follow_works) return FollowStatus::Unsupported;
        value = std::max(value, target);
        return FollowStatus::Applied;
    }
    DoorSample do_sample(ObjRef d) {
        ++sample_calls;
        DoorSample s;
        if (!sample_readable || !still_valid(d)) return s;
        if (opened && post_open_unreadable) return s;
        if (opened && moves && !follow_driven_only) value = std::min(value_max, value + step);
        s.readable = true;
        s.opened = tri(opened);
        s.opened_side = opened ? opened_side : Side::Unknown;
        s.locked = locked;
        s.value = value;
        s.value_side = opened ? opened_side : Side::Unknown;   // closed: no side identity yet
        s.speed = opened && moves ? step : 0.0f;
        s.routine = opened ? 1 : 0;
        s.motion_layer = opened ? tri(motion_layer) : Tri::False;
        s.update_seq = static_cast<uint64_t>(sample_calls);
        return s;
    }
    InvokeResult do_open() {
        if (during_open) during_open();
        if (open_result == InvokeStatus::ReturnedTrue && on_opened != Tri::False) {
            opened = true;
            opened_side = open_side;
        }
        InvokeResult r{open_result};
        if (engine_entered(open_result)) { r.on_opened = on_opened; r.actor_displaced = displaced; }
        return r;
    }
};

class CaptureTransport : public Transport {
public:
    std::vector<Message> sent;
    int fail_after = -1;   // -1 never; otherwise sends beyond this count fail
    std::function<void(const Message&)> on_send;   // observes every attempt, before the outcome
    bool send(const Message& m) override {
        if (on_send) on_send(m);
        if (fail_after >= 0 && static_cast<int>(sent.size()) >= fail_after) return false;
        sent.push_back(m);
        return true;
    }
    template <class T> std::vector<T> of() const {
        std::vector<T> out;
        for (auto& m : sent) if (auto p = std::get_if<T>(&m)) out.push_back(*p);
        return out;
    }
};

class CaptureJournal : public Journal {
public:
    std::vector<JournalRecord> records;
    void write(const JournalRecord& r) override { records.push_back(r); }
    bool has(const std::string& event) const {
        for (auto& r : records) if (r.event == event) return true;
        return false;
    }
};

// Moves peer messages host<->guest through the wire codec (encode -> decode), so
// every hop also exercises the strict contract in both directions.
struct Link {
    CaptureTransport& host_out;
    CaptureTransport& guest_out;
    DoorCore& host;
    DoorCore& guest;
    size_t host_pos = 0, guest_pos = 0;
    bool drop_to_guest = false, drop_to_host = false;
    bool duplicate = false;
    bool hold_to_guest = false;            // keep messages until released (reordering)
    std::function<bool(const Message&)> drop_if;   // selective drop
    std::deque<std::string> held;
    int encode_failures = 0, decode_failures = 0;

    void deliver(DoorCore& to, const Message& m) {
        std::string err;
        auto text = encode(m, &err);
        if (!text) { ++encode_failures; return; }
        auto back = decode(*text, &err);
        if (!back) { ++decode_failures; return; }
        to.receive(*back);
        if (duplicate) to.receive(*back);
    }
    void pump() {
        for (; host_pos < host_out.sent.size(); ++host_pos) {
            const Message& m = host_out.sent[host_pos];
            if (!is_peer_message(m) || drop_to_guest || (drop_if && drop_if(m))) continue;
            if (hold_to_guest && !std::holds_alternative<SelectMsg>(m)) {
                if (auto t = encode(m)) held.push_back(*t);
                continue;
            }
            deliver(guest, m);
        }
        for (; guest_pos < guest_out.sent.size(); ++guest_pos) {
            const Message& m = guest_out.sent[guest_pos];
            if (!is_peer_message(m) || drop_to_host || (drop_if && drop_if(m))) continue;
            deliver(host, m);
        }
    }
    void release_held(bool reversed = false) {
        hold_to_guest = false;
        if (reversed) std::reverse(held.begin(), held.end());
        for (auto& text : held) guest.receive_text(text);
        held.clear();
    }
};

}  // namespace re2net::test
