// Offline transaction tests for the native door core (fake EngineBridge + codec links).
// These establish core semantics only: they do not prove engine behavior, leaf motion,
// collision, the pair/Jack branch or paired gameplay.
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>
#include "fakes.hpp"

using namespace re2net::core;
using namespace re2net::test;

namespace {
int g_fail = 0, g_checks = 0;
std::string g_test;
struct Reg { const char* name; void (*fn)(); };
std::vector<Reg>& reg() { static std::vector<Reg> r; return r; }
}  // namespace
#define CHECK(c) do { ++g_checks; if (!(c)) { ++g_fail; std::printf("  FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, g_test.c_str(), #c); } } while (0)
#define TEST(n) static void n(); static int n##_reg = (reg().push_back({#n, n}), 0); static void n()

namespace {
const DoorKey kDoor{"GasStation_ConvenienceDoor01A_gimmick", 23, 347};
// conn = role-ordered "<host_connection_uuid>:<guest_connection_uuid>" (73 chars),
// Synthetic role-ordered connection UUIDs for fixtures.
const char* kConn = "3f0c5e8a-6b1d-4c2e-9a7f-1d2e3f4a5b6c:8d7e6f5a-4b3c-4d2e-8f1a-0b9c8d7e6f5a";
const char* kConn2 = "3f0c5e8a-6b1d-4c2e-9a7f-1d2e3f4a5b6c:0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d";
const char* kBar = "barrier-9b8c7d6e-5f4a-4b3c-8d2e-1f0a9b8c7d6e";

Fence make_fence() { return Fence{kConn, kBar, "fixture-host-boot-0001", "fixture-guest-boot-0001", 23, 347}; }

struct Pair {
    FakeEngine he, ge;
    CaptureTransport ht, gt;
    CaptureJournal hj, gj;
    DoorCore host{he, ht, hj};
    DoorCore guest{ge, gt, gj};
    Link link{ht, gt, host, guest};
    uint64_t now = 1000;
    Fence hf = make_fence();
    Fence gf = make_fence();
    bool host_consent = true, guest_consent = true, host_playing = true, guest_playing = true;
    explicit Pair(bool settle = true) {
        ge.follow_driven_only = true;   // guest replica door: no local pusher, follows host only
        ge.actor_side_now = Side::Unknown;
        sessions();
        if (settle) step(3);            // capability selection handshake
    }
    void sessions(bool conn = true) {
        host.receive(SessionMsg{hf, Role::Host, conn, host_consent, host_playing});
        guest.receive(SessionMsg{gf, Role::Guest, conn, guest_consent, guest_playing});
    }
    void host_session(bool conn = true) { host.receive(SessionMsg{hf, Role::Host, conn, host_consent, host_playing}); }
    void guest_session(bool conn = true, Role role = Role::Guest) { guest.receive(SessionMsg{gf, role, conn, guest_consent, guest_playing}); }
    void intent(uint64_t req = 1, ActorRole a = ActorRole::P2) { host.receive(IntentMsg{hf, req, kDoor, a}); }
    void step(int n = 1, uint64_t dt = 50) {
        for (int i = 0; i < n; ++i) {
            host.tick(now); link.pump();
            guest.tick(now); link.pump();
            now += dt;
        }
    }
    // Steps until a NEW host operation has finished and both cores are idle.
    void run(int max_steps = 400) {
        size_t start = host.finished().size();
        for (int i = 0; i < max_steps; ++i) {
            step();
            if (host.finished().size() > start && !host.active() && !guest.active()) break;
        }
    }
    void until_guest_opening() {
        for (int i = 0; i < 50 && !(guest.active() && guest.active()->phase == DoorPhase::Opening); ++i) step();
    }
    const OpView& hlast() const { static const OpView none{}; return host.finished().empty() ? none : host.finished().back(); }
    const OpView& glast() const { static const OpView none{}; return guest.finished().empty() ? none : guest.finished().back(); }
};

// One core driven by hand, for exact callback schedules (mirrors the V2 independent
// harness shape: host proposes at 900, then SelectAck + intent at 1000).
struct Solo {
    FakeEngine e;
    CaptureTransport t;
    CaptureJournal j;
    DoorCore c{e, t, j};
    Fence f = make_fence();
    SessionMsg s(Role r) const { return SessionMsg{f, r, true, true, true}; }
    void host() {
        c.receive(s(Role::Host));
        c.tick(900);
        c.receive(SelectAckMsg{f, kDoorImpl, true, Reason::None});
        c.receive(IntentMsg{f, 1, kDoor, ActorRole::P2});
        c.tick(1000);
    }
    void guest() {
        e.follow_driven_only = true;
        c.receive(s(Role::Guest));
        c.receive(SelectMsg{f, kDoorImpl});
        c.receive(ApplyMsg{f, 1, 1, kDoor, Side::B});
        c.tick(1000);
    }
    const OpView& last() const { static const OpView none{}; return c.finished().empty() ? none : c.finished().back(); }
    bool status_with(uint64_t req, Reason r) const {
        for (auto& m : t.of<StatusMsg>()) if (m.req == req && m.reason == r) return true;
        return false;
    }
};

void invariants(const Pair& p) {
    CHECK(p.host.counters().post_final_mutations == 0);
    CHECK(p.guest.counters().post_final_mutations == 0);
    CHECK(p.host.counters().invalid_outbound == 0);
    CHECK(p.guest.counters().invalid_outbound == 0);
    CHECK(p.link.encode_failures == 0 && p.link.decode_failures == 0);
    for (auto* t : {&p.ht, &p.gt}) for (auto& m : t->sent) CHECK(encode(m).has_value());
}
}  // namespace

// ------------------------------------------------------------------ selection
TEST(selection_handshake_precedes_any_write) {
    Pair p;
    CHECK(p.host.selected() && p.guest.selected());
    CHECK(p.ht.of<SelectMsg>().size() == 1 && p.gt.of<SelectAckMsg>().size() == 1);
    CHECK(p.gt.of<SelectAckMsg>()[0].ok);
}

TEST(unacknowledged_selection_blocks_without_write) {
    Pair p(false);
    p.link.drop_if = [](const Message& m) { return std::holds_alternative<SelectAckMsg>(m); };
    p.step(3);
    p.intent();
    p.run();
    CHECK(!p.host.selected());
    CHECK(p.hlast().phase == DoorPhase::Blocked && p.hlast().reason == Reason::NotSelected);
    CHECK(p.he.open_calls == 0 && p.ge.mirror_calls == 0);
}

TEST(guest_refusing_selection_blocks_host) {
    Pair p(false);
    p.ge.caps_value.mirror_open_ok = false;
    p.step(3);
    CHECK(p.gt.of<SelectAckMsg>().size() >= 1 && !p.gt.of<SelectAckMsg>()[0].ok);
    p.intent();
    p.run();
    CHECK(p.hlast().reason == Reason::NotSelected && p.he.open_calls == 0);
}

TEST(guest_never_applies_without_its_own_selection) {
    Pair p(false);
    p.link.drop_if = [](const Message& m) { return std::holds_alternative<SelectMsg>(m); };
    p.guest.receive(ApplyMsg{p.hf, 1, 1, kDoor, Side::B});
    p.step(5);
    CHECK(p.glast().phase == DoorPhase::Blocked && p.glast().reason == Reason::NotSelected);
    CHECK(p.ge.mirror_calls == 0);
}

// ------------------------------------------------------------------ happy paths
TEST(happy_path_open_both_with_single_invocation_each) {
    Pair p;
    p.intent();
    p.run();
    CHECK(p.host.finished().size() == 1);
    CHECK(p.hlast().phase == DoorPhase::OpenBoth);
    CHECK(p.hlast().facts.progress == Tri::True && p.hlast().facts.opened == Tri::True);
    CHECK(p.hlast().facts.on_opened == Tri::True && p.hlast().facts.actor_displaced == Tri::False);
    CHECK(p.hlast().facts.crossed == Tri::False);
    CHECK(p.hlast().guest_result && p.hlast().guest_result->progress == Tri::True);
    CHECK(p.glast().phase == DoorPhase::OpenBoth && p.glast().facts.follow_applied == Tri::True);
    CHECK(p.he.open_calls == 1 && p.he.mirror_calls == 0);
    CHECK(p.ge.mirror_calls == 1 && p.ge.open_calls == 0);
    CHECK(p.host.counters().invocations == 1 && p.guest.counters().invocations == 1);
    CHECK(p.ht.of<ApplyMsg>().size() == 1 && p.ht.of<ApplyMsg>()[0].side == Side::B);
    CHECK(p.ht.of<ProgressMsg>().size() >= 2 && p.ht.of<ProgressMsg>().size() <= 40);
    CHECK(p.hj.has("admitted") && p.hj.has("final"));
    invariants(p);
}

TEST(partner_crossing_on_host_is_named_exactly) {
    Pair p;
    p.intent();
    p.step(4);
    p.he.actor_side_now = Side::B;
    p.run();
    CHECK(p.hlast().phase == DoorPhase::OpenBothPartnerCrossedHost);
    CHECK(std::string(to_string(p.hlast().phase)) == "open_both_partner_crossed_host");
    CHECK(p.hlast().facts.crossed == Tri::True);
    invariants(p);
}

TEST(scene_change_after_crossing_is_completion_not_interruption) {
    Pair p;
    p.intent();
    p.step(4);
    p.he.actor_side_now = Side::B;
    p.step(1);
    p.hf.scene_room = 348;
    p.host_session();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::OpenBothPartnerCrossedHost);
    CHECK(p.hlast().reason == Reason::None);
}

TEST(raw_values_beyond_unit_range_are_carried_not_clamped) {
    Pair p;
    p.he.step = 7.5f;
    p.he.value_max = 100.0f;
    p.intent();
    p.run();
    bool big = false;
    for (auto& pm : p.ht.of<ProgressMsg>()) if (pm.value.milli > 1000) big = true;
    CHECK(big);
}

// ------------------------------------------------------------------ duplicates / ordering
TEST(duplicate_intent_does_not_start_second_operation) {
    Pair p;
    p.intent(1); p.intent(1);
    p.step(2);
    p.intent(1);
    p.run();
    CHECK(p.host.finished().size() == 1 && p.host.counters().duplicates >= 2 && p.he.open_calls == 1);
}

TEST(second_intent_while_busy_is_refused_without_write) {
    Pair p;
    p.intent(1);
    p.step(2);
    p.intent(2);
    p.run();
    CHECK(p.host.finished().size() == 1 && p.he.open_calls == 1);
    bool busy = false;
    for (auto& s : p.ht.of<StatusMsg>()) if (s.req == 2 && s.reason == Reason::Busy) busy = true;
    CHECK(busy);
}

TEST(duplicate_delivery_returns_same_guest_outcome_once_invoked) {
    Pair p;
    p.link.duplicate = true;
    p.intent();
    p.run();
    CHECK(p.ge.mirror_calls == 1 && p.hlast().phase == DoorPhase::OpenBoth);
    ApplyMsg a = p.ht.of<ApplyMsg>()[0];
    size_t before = p.gt.of<ResultMsg>().size();
    p.guest.receive(a);
    p.step(2);
    CHECK(p.ge.mirror_calls == 1);
    CHECK(p.gt.of<ResultMsg>().size() == before + 1 && p.gt.of<ResultMsg>().back().phase == p.glast().phase);
    invariants(p);
}

TEST(messages_ahead_of_apply_are_buffered_and_honored) {
    Pair p;
    p.link.hold_to_guest = true;
    p.intent();
    for (int i = 0; i < 50 && p.ht.of<ProgressMsg>().size() < 3; ++i) p.step();
    CHECK(p.link.held.size() >= 4);
    p.link.release_held(/*reversed=*/true);
    p.run();
    CHECK(p.ge.mirror_calls == 1 && p.glast().phase == DoorPhase::OpenBoth && p.hlast().phase == DoorPhase::OpenBoth);
}

TEST(full_stream_flood_ahead_of_apply_overflows_honestly) {
    Pair p;
    p.link.hold_to_guest = true;
    p.intent();
    for (int i = 0; i < 300 && p.ht.of<HostDoneMsg>().empty(); ++i) p.step();
    CHECK(p.link.held.size() > 32);
    p.link.release_held(/*reversed=*/true);
    p.run(600);
    CHECK(p.guest.counters().inbox_overflow > 0 && p.ge.mirror_calls == 0);
    CHECK(p.hlast().phase == DoorPhase::Uncertain && p.hlast().reason == Reason::GuestTimeout);
}

TEST(old_apply_after_newer_is_dropped) {
    Pair p;
    p.guest.receive(ApplyMsg{p.hf, 5, 5, kDoor, Side::B});
    p.step(1);
    p.guest.receive(ApplyMsg{p.hf, 4, 4, kDoor, Side::B});
    p.step(1);
    CHECK(p.guest.counters().out_of_order >= 1 && p.ge.mirror_calls == 1);
}

TEST(frames_with_matching_op_but_foreign_fence_are_ignored) {
    Pair p;
    p.intent();
    p.step(3);
    Fence other = p.hf;
    other.connection = "a1b2c3d4-0000-4000-8000-000000000001";
    p.guest.receive(ProgressMsg{other, 1, 99, WireValue{900, false}});
    p.guest.receive(HostDoneMsg{other, 1, Tri::True, Tri::True, Reason::None});
    p.host.receive(ResultMsg{other, 1, DoorPhase::OpenBoth, Reason::None, Tri::True, Tri::True});
    p.run();
    CHECK(p.guest.counters().foreign_fence >= 2 && p.host.counters().foreign_fence >= 1);
    CHECK(p.hlast().phase == DoorPhase::OpenBoth);
}

TEST(cross_direction_frames_are_rejected) {
    Pair p;
    p.guest.receive(ResultMsg{p.hf, 1, DoorPhase::OpenBoth, Reason::None, Tri::True, Tri::True});
    p.host.receive(ProgressMsg{p.hf, 1, 1, WireValue{10, false}});
    p.host.receive(ApplyMsg{p.hf, 1, 1, kDoor, Side::A});
    p.step(2);
    CHECK(p.guest.counters().bad_messages >= 1 && p.host.counters().bad_messages >= 2);
    CHECK(p.he.open_calls == 0 && p.ge.mirror_calls == 0);
}

// ------------------------------------------------------------------ scene / fence / consent
TEST(guest_waits_for_delayed_scene_then_applies) {
    Pair p;
    p.gf.scene_room = 346;
    p.guest_session();
    p.intent();
    p.step(10);
    CHECK(p.guest.active() && p.guest.active()->phase == DoorPhase::WaitingPartnerScene && p.ge.mirror_calls == 0);
    p.gf.scene_room = 347;
    p.guest_session();
    p.run();
    CHECK(p.ge.mirror_calls == 1 && p.hlast().phase == DoorPhase::OpenBoth);
}

TEST(guest_scene_timeout_blocks_without_write_and_host_reports_mismatch) {
    Pair p;
    p.gf.scene_room = 346;
    p.guest_session();
    p.intent();
    p.run(600);
    CHECK(p.ge.mirror_calls == 0);
    CHECK(p.glast().phase == DoorPhase::Blocked && p.glast().reason == Reason::SceneTimeout);
    CHECK(p.hlast().phase == DoorPhase::Mismatch);
}

TEST(disconnect_before_invocation_blocks_with_zero_writes) {
    Pair p;
    p.intent();
    p.host_session(false);
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Blocked && p.hlast().reason == Reason::Disconnected);
    CHECK(p.he.open_calls == 0 && p.ht.of<ApplyMsg>().empty());
}

TEST(disconnect_during_observation_interrupts_without_retry) {
    Pair p;
    p.intent();
    p.step(3);
    CHECK(p.host.active() && p.host.active()->phase == DoorPhase::Opening);
    p.host_session(false);
    p.guest_session(false);
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::Disconnected);
    CHECK(p.he.open_calls == 1);
    invariants(p);
}

TEST(barrier_replacement_before_invocation_blocks) {
    Pair p;
    p.intent();
    p.hf.barrier = "barrier-replacement-0001";
    p.host_session();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Blocked && p.hlast().reason == Reason::FenceChanged && p.he.open_calls == 0);
}

TEST(same_fence_ready_revocation_retires_and_stops_guest_writes) {
    Pair p;
    p.intent();
    p.until_guest_opening();
    CHECK(p.guest.active().has_value());
    int follows_before = p.ge.follow_calls;
    p.host_consent = false; p.guest_consent = false;
    p.sessions();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::ConsentLost);
    CHECK(p.glast().phase == DoorPhase::Interrupted && p.glast().reason == Reason::ConsentLost);
    CHECK(p.ge.follow_calls == follows_before);
    CHECK(p.he.open_calls == 1 && p.ge.mirror_calls == 1);
    invariants(p);
}

TEST(role_change_retires_operation) {
    Pair p;
    p.intent();
    p.until_guest_opening();
    p.guest_session(true, Role::Host);
    p.step(3);
    CHECK(p.glast().phase == DoorPhase::Interrupted && p.glast().reason == Reason::RoleChanged);
}

TEST(pause_suspends_guest_follow_writes_without_retiring) {
    Pair p;
    p.intent();
    p.until_guest_opening();
    p.guest_playing = false;
    p.guest_session();
    int before = p.ge.follow_calls;
    p.step(3);
    CHECK(p.ge.follow_calls == before);
    CHECK(p.guest.counters().writes_refused_scope > 0);
    CHECK(p.guest.active().has_value());
    p.guest_playing = true;
    p.guest_session();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::OpenBoth);
}

// ------------------------------------------------------------------ incarnation / reentrancy
TEST(door_replaced_during_invocation_interrupts_after_write) {
    Pair p;
    p.he.during_open = [&] { p.he.door_inc = 2; };
    p.intent();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::Stale);
    CHECK(p.he.open_calls == 1);
}

TEST(actor_replaced_during_observation_interrupts) {
    Pair p;
    p.intent();
    p.step(3);
    p.he.p2_inc = 9;
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::Stale && p.he.open_calls == 1);
}

TEST(reentrant_tick_inside_invocation_is_refused) {
    Pair p;
    p.he.during_open = [&] { p.host.tick(p.now); p.host.receive(IntentMsg{p.hf, 9, kDoor, ActorRole::P2}); };
    p.intent();
    p.run();
    CHECK(p.host.counters().nested_ticks == 1 && p.he.open_calls == 1);
    CHECK(p.host.finished().front().phase == DoorPhase::OpenBoth);
}

TEST(disconnect_signalled_inside_invocation_retires_before_any_follow_up) {
    Pair p;
    p.he.during_open = [&] { p.host.receive(SessionMsg{p.hf, Role::Host, false, true, true}); };
    p.intent();
    p.run();
    CHECK(p.he.open_calls == 1);
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::Disconnected);
    CHECK(p.ht.of<ApplyMsg>().empty());
}

// ------------------------------------------------------------------ native results
TEST(native_false_is_uncertain_with_no_fallback_or_apply) {
    Pair p;
    p.he.open_result = InvokeStatus::ReturnedFalse;
    p.intent();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Uncertain && p.hlast().reason == Reason::NativeFalse);
    CHECK(p.hlast().facts.engine_entered == Tri::True && p.hlast().facts.native_true == Tri::False);
    CHECK(p.he.open_calls == 1 && p.ht.of<ApplyMsg>().empty() && p.ge.mirror_calls == 0);
}

TEST(native_exception_is_uncertain_once) {
    Pair p;
    p.he.open_result = InvokeStatus::Exception;
    p.intent();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Uncertain && p.hlast().reason == Reason::NativeException);
    CHECK(p.hlast().facts.native_true == Tri::Unknown && p.he.open_calls == 1);
}

TEST(true_without_onopened_is_no_open_mutation) {
    Pair p;
    p.he.on_opened = Tri::False;
    p.intent();
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Uncertain && p.hlast().reason == Reason::NoOpenMutation);
    CHECK(p.hlast().facts.native_true == Tri::True && p.hlast().facts.on_opened == Tri::False);
    CHECK(p.he.open_calls == 1 && p.ht.of<ApplyMsg>().empty() && p.ge.mirror_calls == 0);
}

TEST(actor_displacement_inside_call_is_recorded_as_a_fact) {
    Pair p;
    p.he.displaced = Tri::True;
    p.intent();
    p.run();
    CHECK(p.hlast().facts.actor_displaced == Tri::True);
}

TEST(true_return_and_isopened_without_leaf_progress_is_never_success) {
    Pair p;
    p.he.moves = false;
    p.intent();
    p.run();
    CHECK(p.hlast().facts.native_true == Tri::True && p.hlast().facts.opened == Tri::True);
    CHECK(p.hlast().facts.progress == Tri::False);
    CHECK(p.hlast().phase != DoorPhase::OpenBoth && p.hlast().phase != DoorPhase::OpenBothPartnerCrossedHost);
}

TEST(unreadable_post_open_samples_keep_progress_unknown) {
    Pair p;
    p.he.post_open_unreadable = true;
    p.intent();
    p.run();
    CHECK(p.hlast().facts.progress == Tri::Unknown && p.hlast().facts.readable_samples == 0);
    CHECK(p.hlast().phase == DoorPhase::Uncertain);
}

TEST(host_open_guest_closed_is_mismatch) {
    Pair p;
    p.ge.follow_works = false;
    p.intent();
    p.run();
    CHECK(p.hlast().facts.progress == Tri::True && p.glast().facts.progress == Tri::False);
    CHECK(p.hlast().phase == DoorPhase::Mismatch);
}

TEST(follow_backend_disabled_replica_without_pusher_is_mismatch) {
    Pair p;
    p.ge.caps_value.follow_ok = false;
    p.intent();
    p.run();
    CHECK(p.ge.follow_calls == 0 && p.hlast().phase == DoorPhase::Mismatch);
}

TEST(guest_door_locked_is_blocked_and_host_mismatch) {
    Pair p;
    p.ge.locked = Tri::True;
    p.intent();
    p.run();
    CHECK(p.glast().phase == DoorPhase::Blocked && p.glast().reason == Reason::DoorLocked && p.ge.mirror_calls == 0);
    CHECK(p.hlast().phase == DoorPhase::Mismatch && p.hlast().reason == Reason::DoorLocked);
}

TEST(guest_silence_times_out_as_uncertain) {
    Pair p;
    p.link.drop_to_host = true;
    p.intent();
    p.run(600);
    CHECK(p.hlast().phase == DoorPhase::Uncertain && p.hlast().reason == Reason::GuestTimeout);
}

// ------------------------------------------------------------------ cancellation / overflow
TEST(cancellation_before_write_blocks) {
    Pair p;
    p.intent();
    p.host.receive(CancelMsg{p.hf, 1});
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Blocked && p.hlast().reason == Reason::Cancelled && p.he.open_calls == 0);
}

TEST(cancellation_during_observation_interrupts) {
    Pair p;
    p.intent();
    p.step(3);
    p.host.receive(CancelMsg{p.hf, 1});
    p.run();
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::Cancelled && p.he.open_calls == 1);
    invariants(p);
}

TEST(inbox_overflow_retires_active_operation) {
    Pair p;
    p.intent();
    p.step(3);
    for (int i = 0; i < 40; ++i) p.host.receive(StatusMsg{});
    p.run();
    CHECK(p.host.counters().inbox_overflow > 0);
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::Overflow && p.he.open_calls == 1);
}

TEST(transport_backpressure_retires_honestly) {
    Pair p;
    p.intent();
    p.step(2);
    p.ht.fail_after = static_cast<int>(p.ht.sent.size());
    p.run();
    CHECK(p.host.counters().send_failures > 0);
    CHECK(p.hlast().phase == DoorPhase::Interrupted && p.hlast().reason == Reason::Overflow && p.he.open_calls == 1);
}

// ------------------------------------------------------------------ admission guards
TEST(admission_guards_refuse_without_any_write) {
    struct Case { const char* name; std::function<void(Pair&)> setup; Reason want; };
    std::vector<Case> cases = {
        {"host_far", [](Pair& p) { p.he.p1_distance = 8.5f; }, Reason::HostFar},
        {"distance_unknown", [](Pair& p) { p.he.p1_distance.reset(); }, Reason::DistanceUnknown},
        {"p1_missing", [](Pair& p) { p.he.p1_present = false; }, Reason::DistanceUnknown},
        {"p2_missing", [](Pair& p) { p.he.p2_present = false; }, Reason::ActorMissing},
        {"door_missing", [](Pair& p) { p.he.door_count = 0; }, Reason::DoorMissing},
        {"door_duplicate", [](Pair& p) { p.he.door_count = 2; }, Reason::DoorDuplicate},
        {"door_not_loaded", [](Pair& p) { p.he.door_loaded = false; }, Reason::DoorNotLoaded},
        {"locked", [](Pair& p) { p.he.locked = Tri::True; }, Reason::DoorLocked},
        {"lock_unknown", [](Pair& p) { p.he.locked = Tri::Unknown; }, Reason::LockUnknown},
        {"already_open", [](Pair& p) { p.he.opened = true; p.he.opened_side = Side::A; }, Reason::AlreadyOpen},
        {"unreadable", [](Pair& p) { p.he.sample_readable = false; }, Reason::LockUnknown},
        {"caps", [](Pair& p) { p.he.caps_value.actor_open_ok = false; }, Reason::NotSelected},
        {"no_consent", [](Pair& p) { p.host_consent = false; p.host_session(); }, Reason::NoConsent},
        {"not_playing", [](Pair& p) { p.host_playing = false; p.host_session(); }, Reason::NotPlaying},
    };
    for (auto& c : cases) {
        Pair p(false);
        c.setup(p);
        p.step(3);
        p.intent();
        p.run();
        bool ok = !p.host.finished().empty() && p.hlast().phase == DoorPhase::Blocked && p.hlast().reason == c.want;
        if (!ok) std::printf("    case %s -> %s/%s\n", c.name, to_string(p.hlast().phase), to_string(p.hlast().reason));
        CHECK(ok);
        CHECK(p.he.open_calls == 0 && p.ht.of<ApplyMsg>().empty());
    }
    Pair q;
    q.intent(1, ActorRole::P1);
    q.run();
    CHECK(q.hlast().reason == Reason::Unsupported && q.he.open_calls == 0);
}

TEST(guest_never_mutates_without_host_apply) {
    Pair p;
    p.guest.receive(IntentMsg{p.gf, 1, kDoor, ActorRole::P2});
    p.step(5);
    CHECK(p.ge.mirror_calls == 0 && p.ge.open_calls == 0 && p.guest.counters().bad_messages == 1);
}

// ------------------------------------------------------------------ V2 review 1319 regressions
// 1. Callback-queued authority changes fence later writes and final claims.
TEST(r1319_consent_revoked_inside_admission_sample_prevents_open) {
    Solo x;
    bool once = false;
    x.e.in_sample = [&] {
        if (once) return;
        once = true;
        auto s = x.s(Role::Host);
        s.consent = false;
        x.c.receive(s);
        x.c.tick(1001);
    };
    x.host();
    CHECK(x.e.open_calls == 0);
    CHECK(x.c.counters().nested_ticks == 1);
    CHECK(x.last().phase == DoorPhase::Blocked && x.last().reason == Reason::NoConsent);
    CHECK(x.c.permit_revision() >= 1);
}

TEST(r1319_disconnect_queued_inside_follow_cannot_finish_success) {
    Solo x;
    x.guest();
    bool once = false;
    x.e.in_follow = [&] {
        if (once) return;
        once = true;
        auto s = x.s(Role::Guest);
        s.connected = false;
        x.c.receive(s);
        x.c.tick(1051);
    };
    x.c.receive(ProgressMsg{x.f, 1, 1, WireValue{700, false}});
    x.c.receive(HostDoneMsg{x.f, 1, Tri::True, Tri::Unknown, Reason::None});
    x.c.tick(1050);
    CHECK(x.e.follow_calls == 1);
    CHECK(x.last().phase == DoorPhase::Interrupted && x.last().reason == Reason::Disconnected);
    CHECK(x.t.of<ResultMsg>().size() == 1 && x.t.of<ResultMsg>()[0].phase == DoorPhase::Interrupted);
}

TEST(r1319_queued_regrant_cannot_hide_a_revocation) {
    Solo x;
    x.host();
    bool once = false;
    x.e.in_sample = [&] {
        if (once) return;
        once = true;
        auto down = x.s(Role::Host);
        down.consent = false;
        x.c.receive(down);
        x.c.receive(x.s(Role::Host));   // consent again, queued behind the revocation
    };
    x.c.tick(1050);
    CHECK(x.t.of<ApplyMsg>().empty());
    CHECK(x.last().phase == DoorPhase::Interrupted && x.last().reason == Reason::ConsentLost);
    CHECK(x.e.open_calls == 1);
}

TEST(r1319_cancel_queued_inside_sample_fences_the_apply) {
    Solo x;
    x.host();
    bool once = false;
    x.e.in_sample = [&] { if (!once) { once = true; x.c.receive(CancelMsg{x.f, 1}); } };
    x.c.tick(1050);
    CHECK(x.t.of<ApplyMsg>().empty());
    CHECK(x.last().phase == DoorPhase::Interrupted && x.last().reason == Reason::Cancelled);
}

// 2. Revalidate scope and object incarnation after every external callback.
TEST(r1319_door_replaced_inside_sample_never_authorizes_apply) {
    Solo x;
    x.host();
    bool once = false;
    x.e.in_sample = [&] { if (!once) { once = true; ++x.e.door_inc; } };
    x.c.tick(1050);
    CHECK(x.t.of<ApplyMsg>().empty());
    CHECK(x.last().phase == DoorPhase::Interrupted && x.last().reason == Reason::Stale);
    CHECK(x.c.counters().revalidation_retired == 1);
}

TEST(r1319_door_replaced_inside_follow_after_progress_cannot_finish_success) {
    Solo x;
    x.guest();
    x.c.receive(ProgressMsg{x.f, 1, 1, WireValue{500, false}});
    x.c.tick(1050);
    CHECK(x.c.active() && x.c.active()->facts.progress == Tri::True);
    bool once = false;
    x.e.in_follow = [&] { if (!once) { once = true; ++x.e.door_inc; } };
    x.c.receive(HostDoneMsg{x.f, 1, Tri::True, Tri::Unknown, Reason::None});
    x.c.tick(1100);
    CHECK(x.last().phase == DoorPhase::Interrupted && x.last().reason == Reason::Stale);
    CHECK(x.last().phase != DoorPhase::OpenBoth);
}

TEST(r1319_admission_facts_are_revalidated_before_the_write) {
    Solo x;
    bool once = false;
    x.e.in_sample = [&] { if (!once) { once = true; ++x.e.door_inc; } };
    x.host();
    CHECK(x.e.open_calls == 0);
    CHECK(x.last().phase == DoorPhase::Blocked && x.last().reason == Reason::Stale);
}

// 3. Exception-safe tick guard with an honest outcome and no retry.
TEST(r1319_thrown_exception_before_write_restores_guard_and_blocks) {
    Solo x;
    x.e.throw_sample_at = 1;   // the admission sample
    x.host();
    CHECK(x.c.counters().callback_exceptions == 1 && x.c.faulted());
    CHECK(x.e.open_calls == 0);
    CHECK(x.last().phase == DoorPhase::Blocked && x.last().reason == Reason::NativeException);
    x.c.tick(1050);
    CHECK(x.c.counters().nested_ticks == 0);
    CHECK(x.j.has("callback_exception"));
    CHECK(x.status_with(1, Reason::NativeException));   // deferred status went out on the next tick
    x.c.receive(IntentMsg{x.f, 2, kDoor, ActorRole::P2});
    x.c.tick(1100);
    CHECK(x.e.open_calls == 0 && x.last().reason == Reason::Unsupported);   // faulted: no retry, no new write
    CHECK(!x.c.caps().ok);
}

TEST(r1319_thrown_exception_after_write_is_uncertain_and_owes_host_done) {
    Solo x;
    x.host();
    x.c.tick(1050);
    CHECK(x.t.of<ApplyMsg>().size() == 1);
    x.e.throw_sample_at = x.e.sample_calls + 1;
    x.c.tick(1150);
    CHECK(x.c.counters().callback_exceptions == 1);
    CHECK(x.last().phase == DoorPhase::Uncertain && x.last().reason == Reason::NativeException);
    CHECK(x.e.open_calls == 1);
    x.c.tick(1200);
    CHECK(x.c.counters().nested_ticks == 0);
    CHECK(x.t.of<HostDoneMsg>().size() == 1 && x.t.of<HostDoneMsg>()[0].reason == Reason::NativeException);
}

TEST(r1319_guest_exception_defers_its_result) {
    Solo x;
    x.guest();
    x.e.throw_sample_at = x.e.sample_calls + 1;
    x.c.receive(ProgressMsg{x.f, 1, 1, WireValue{500, false}});
    x.c.tick(1050);
    CHECK(x.last().phase == DoorPhase::Uncertain && x.last().reason == Reason::NativeException);
    CHECK(x.t.of<ResultMsg>().empty());
    x.c.tick(1100);
    CHECK(x.t.of<ResultMsg>().size() == 1 && x.t.of<ResultMsg>()[0].reason == Reason::NativeException);
    x.c.receive(ApplyMsg{x.f, 1, 1, kDoor, Side::B});   // duplicate delivery returns the same outcome
    x.c.tick(1150);
    CHECK(x.t.of<ResultMsg>().size() == 2 && x.e.mirror_calls == 1);
}

// 4. Scope order: retire the old-scope operation before consuming fresh-scope requests.
TEST(r1319_new_scope_retires_old_operation_before_fresh_requests) {
    Solo x;
    x.host();
    CHECK(x.c.active() && x.c.active()->phase == DoorPhase::Opening);
    Fence f2 = x.f;
    f2.connection = kConn2;
    x.c.receive(SessionMsg{f2, Role::Host, true, true, true});
    x.c.receive(SelectAckMsg{f2, kDoorImpl, true, Reason::None});   // unsolicited: no door_select under f2 yet
    x.c.receive(IntentMsg{f2, 1, kDoor, ActorRole::P2});
    x.c.tick(1050);
    CHECK(x.c.finished().size() == 2);
    CHECK(x.c.finished()[0].fence.connection == kConn && x.c.finished()[0].phase == DoorPhase::Interrupted &&
          x.c.finished()[0].reason == Reason::FenceChanged);
    CHECK(!x.status_with(1, Reason::Busy));
    CHECK(x.c.counters().unsolicited_acks == 1);
    CHECK(x.last().fence.connection == kConn2 && x.last().reason == Reason::NotSelected);
    CHECK(x.c.legacy_reserved() && x.e.open_calls == 1);   // reserved for f2 before its door_select
    // The guest answers the f2 proposal: the next request is admitted in the fresh scope.
    x.e.opened = false;
    x.e.value = 0.0f;
    x.c.receive(SelectAckMsg{f2, kDoorImpl, true, Reason::None});
    x.c.receive(IntentMsg{f2, 2, kDoor, ActorRole::P2});
    x.c.tick(1100);
    CHECK(x.c.active() && x.c.active()->fence.connection == kConn2 && x.e.open_calls == 2);
}

TEST(r1319_busy_refusal_does_not_consume_the_request) {
    Solo x;
    x.host();
    x.c.receive(IntentMsg{x.f, 2, kDoor, ActorRole::P2});
    x.c.tick(1050);
    CHECK(x.status_with(2, Reason::Busy));
    x.c.receive(CancelMsg{x.f, 1});
    x.c.tick(1100);
    CHECK(!x.c.active());
    x.e.opened = false;
    x.e.value = 0.0f;
    x.c.receive(IntentMsg{x.f, 2, kDoor, ActorRole::P2});   // the same request, retried
    x.c.tick(1150);
    CHECK(x.c.counters().duplicates == 0);
    CHECK(x.c.active() && x.c.active()->req == 2 && x.e.open_calls == 2);
}

// Exclusive legacy reservation.
TEST(r1319_host_reserves_before_select_and_guest_before_ack) {
    Pair p(false);
    bool host_at_select = false, guest_at_ack = false;
    p.ht.on_send = [&](const Message& m) { if (std::holds_alternative<SelectMsg>(m)) host_at_select = p.host.legacy_reserved(); };
    p.gt.on_send = [&](const Message& m) { if (std::holds_alternative<SelectAckMsg>(m)) guest_at_ack = p.guest.legacy_reserved(); };
    p.step(3);
    CHECK(host_at_select && guest_at_ack);
    CHECK(p.host.selected() && p.guest.selected());
    CHECK(p.hj.has("legacy_reserved") && p.gj.has("legacy_reserved"));
}

TEST(r1319_ambiguous_select_send_or_timeout_never_releases) {
    Pair p(false);
    p.ht.fail_after = 0;   // every host send fails locally
    p.step(3);
    CHECK(p.host.legacy_reserved() && !p.host.selected());
    p.step(60);            // three seconds of unanswered retries
    CHECK(p.host.legacy_reserved() && !p.host.selected());
    CHECK(!p.hj.has("legacy_released"));
}

TEST(r1319_peer_refusal_releases_host_and_guest_never_reserves) {
    Pair p(false);
    p.ge.caps_value.mirror_open_ok = false;
    p.step(3);
    CHECK(!p.host.legacy_reserved() && !p.guest.legacy_reserved());
    p.step(60);
    CHECK(p.ht.of<SelectMsg>().size() == 1);   // no re-proposal within a refused scope
}

TEST(r1319_scope_change_releases_and_requires_a_new_handshake) {
    Pair p;
    CHECK(p.host.legacy_reserved() && p.guest.legacy_reserved());
    p.hf.connection = kConn2;
    p.gf.connection = kConn2;
    p.sessions();
    p.step(1);
    CHECK(p.hj.has("legacy_released") && p.gj.has("legacy_released"));
    p.step(3);
    CHECK(p.host.selected() && p.guest.selected() && p.ht.of<SelectMsg>().size() == 2);
}

TEST(r1319_unsolicited_ack_cannot_select) {
    Solo x;
    x.c.receive(x.s(Role::Host));
    x.c.receive(SelectAckMsg{x.f, kDoorImpl, true, Reason::None});
    x.c.receive(IntentMsg{x.f, 1, kDoor, ActorRole::P2});
    x.c.tick(1000);
    CHECK(x.c.counters().unsolicited_acks == 1 && !x.c.selected());
    CHECK(x.e.open_calls == 0 && x.last().reason == Reason::NotSelected);
}

TEST(r1319_pair_connection_identity_fits_the_contract) {
    std::string conn = kConn;
    CHECK(conn.size() == 73 && conn[36] == ':');
    CHECK(make_fence().valid());
    auto text = encode(CancelMsg{make_fence(), 1});
    CHECK(text && text->find(kConn) != std::string::npos);
}

// ------------------------------------------------------------------ R1328 adapter follow-up (core side)
TEST(r1328_local_reset_ends_local_authority_and_requires_fresh_session) {
    Solo x;
    x.host();
    CHECK(x.c.active() && x.c.selected() && x.c.legacy_reserved());
    x.c.receive(IntentMsg{x.f, 2, kDoor, ActorRole::P2});   // queued under the old local connection
    x.c.local_reset("test");
    CHECK(!x.c.session().connected && !x.c.session().consent && !x.c.selected());
    CHECK(x.c.legacy_reserved());                             // peer scope unchanged: no unilateral release
    x.c.tick(1050);
    CHECK(x.last().phase == DoorPhase::Interrupted && x.last().reason == Reason::Disconnected);
    CHECK(!x.status_with(2, Reason::Busy) && x.c.counters().local_resets == 1);   // queued intent discarded
    x.e.opened = false;
    x.e.value = 0.0f;
    x.c.receive(IntentMsg{x.f, 3, kDoor, ActorRole::P2});   // old-fence intent, no fresh session
    x.c.tick(1100);
    CHECK(x.e.open_calls == 1 && x.last().phase == DoorPhase::Blocked && x.last().reason == Reason::Disconnected);
    x.c.receive(x.s(Role::Host));                             // fresh session: re-handshake, then act
    x.c.tick(1150);
    x.c.receive(SelectAckMsg{x.f, kDoorImpl, true, Reason::None});
    x.c.receive(IntentMsg{x.f, 4, kDoor, ActorRole::P2});
    x.c.tick(2200);
    CHECK(x.e.open_calls == 2 && x.c.active().has_value());
}

TEST(r1328_undecodable_local_text_resets_authority) {
    Solo x;
    x.host();
    CHECK(!x.c.receive_text("{\"v\":1,\"t\":\"session\",\"bogus\":1}"));
    CHECK(x.c.counters().local_resets == 1 && !x.c.session().connected);
    x.c.tick(1050);
    CHECK(x.last().reason == Reason::Disconnected);
}

TEST(r1328_core_inbox_overflow_is_a_local_loss) {
    Solo x;
    x.host();
    for (int i = 0; i < 40; ++i) x.c.receive(StatusMsg{});
    CHECK(x.c.take_local_loss() && !x.c.take_local_loss());
    x.c.tick(1050);
    CHECK(x.last().phase == DoorPhase::Interrupted && x.last().reason == Reason::Overflow);
}

TEST(r1328_side_switch_alone_never_proves_motion) {
    // The open baseline is read on side B; every later value comes from the side-A work
    // (0.9 there). The leaf itself never moves, so this must never become progress.
    struct SwitchAfterBaseline : FakeEngine {
        int post_open = 0;
        DoorSample sample(ObjRef d) override {
            DoorSample s = FakeEngine::sample(d);
            if (s.value && opened && ++post_open > 1) { s.value_side = Side::A; s.value = 0.9f; }
            return s;
        }
    };
    SwitchAfterBaseline e;
    e.moves = false;
    CaptureTransport t;
    CaptureJournal j;
    DoorCore c{e, t, j};
    Fence f = make_fence();
    c.receive(SessionMsg{f, Role::Host, true, true, true});
    c.tick(900);
    c.receive(SelectAckMsg{f, kDoorImpl, true, Reason::None});
    c.receive(IntentMsg{f, 1, kDoor, ActorRole::P2});
    c.tick(1000);
    CHECK(j.has("open_baseline"));
    for (uint64_t now = 1050; now < 1400; now += 50) c.tick(now);
    CHECK(c.active() && c.active()->facts.progress != Tri::True);
    CHECK(c.counters().baseline_resets == 1 && c.active()->facts.max_delta == 0.0f);
    c.tick(8000);              // observation window over: host-local outcome is final
    CHECK(c.active() && c.active()->facts.progress == Tri::False);
}

TEST(r1328_unknown_value_side_is_never_compared_with_a_known_one) {
    struct SideFlip : FakeEngine {
        int n = 0;
        DoorSample sample(ObjRef d) override {
            DoorSample s = FakeEngine::sample(d);
            if (s.value && opened) { s.value_side = (++n % 2) ? Side::A : Side::B; s.value = (n % 2) ? 0.0f : 0.9f; }
            return s;
        }
    };
    SideFlip e;
    e.moves = false;
    CaptureTransport t;
    CaptureJournal j;
    DoorCore c{e, t, j};
    Fence f = make_fence();
    c.receive(SessionMsg{f, Role::Host, true, true, true});
    c.tick(900);
    c.receive(SelectAckMsg{f, kDoorImpl, true, Reason::None});
    c.receive(IntentMsg{f, 1, kDoor, ActorRole::P2});
    c.tick(1000);
    for (uint64_t now = 1050; now < 1600; now += 50) c.tick(now);
    CHECK(c.active() && c.active()->facts.progress != Tri::True);   // alternating sides: every sample re-acquires
    CHECK(c.counters().baseline_resets >= 5);
}

// ------------------------------------------------------------------ R1356 door-scoped eligibility lease
TEST(r1356_lease_follows_a_successful_open_and_ends_with_the_operation) {
    Pair p;
    p.he.report.injected = 3;
    p.ge.report.injected = 2;
    p.intent();
    p.step(3);
    CHECK(p.he.lease_active && p.he.lease_door.token == 100 && p.he.lease_actor.token == 2);   // door + partner (P2)
    p.run();
    CHECK(p.hlast().phase == DoorPhase::OpenBoth);
    CHECK(!p.he.lease_active && !p.ge.lease_active);
    CHECK(p.hlast().facts.partner_eligible == Tri::True && p.glast().facts.partner_eligible == Tri::True);
    CHECK(p.host.counters().leases >= 1 && p.host.counters().lease_releases >= 1);
    invariants(p);
}

TEST(r1356_no_lease_without_a_successful_open) {
    for (int k = 0; k < 3; ++k) {
        Pair p;
        if (k == 0) p.he.open_result = InvokeStatus::ReturnedFalse;
        if (k == 1) p.he.on_opened = Tri::False;              // true without the open: no_open_mutation
        if (k == 2) p.he.locked = Tri::True;                  // refused before any write
        p.intent();
        p.run();
        CHECK(p.he.lease_calls == 0 && !p.he.lease_active);
        CHECK(p.hlast().facts.partner_eligible == Tri::Unknown);
    }
}

TEST(r1356_revocation_inside_a_callback_releases_the_lease_immediately) {
    Solo x;
    x.host();
    CHECK(x.e.lease_active);
    bool released_in_callback = false;
    bool once = false;
    x.e.in_sample = [&] {
        if (once) return;
        once = true;
        auto s = x.s(Role::Host);
        s.consent = false;
        x.c.receive(s);
        released_in_callback = !x.e.lease_active;   // before the core's tick resumes
    };
    x.c.tick(1050);
    CHECK(released_in_callback);
    CHECK(x.last().reason == Reason::ConsentLost && !x.e.lease_active);
}

TEST(r1356_pause_suspends_the_lease_and_resume_regrants_it) {
    Solo x;
    x.host();
    CHECK(x.e.lease_active && x.e.lease_calls == 1);
    auto s = x.s(Role::Host);
    s.playing = false;
    x.c.receive(s);
    CHECK(!x.e.lease_active);                                  // immediately, while still queued
    x.c.tick(1050);
    CHECK(!x.e.lease_active && x.c.active().has_value());
    x.c.receive(x.s(Role::Host));
    x.c.tick(1100);
    CHECK(x.e.lease_active && x.e.lease_calls == 2);
}

TEST(r1356_every_retirement_path_releases_the_lease) {
    {   // local channel change
        Solo x;
        x.host();
        x.c.local_reset("test");
        CHECK(!x.e.lease_active);
    }
    {   // contained C++ exception
        Solo x;
        x.host();
        x.e.throw_sample_at = x.e.sample_calls + 1;
        x.c.tick(1050);
        CHECK(x.c.faulted() && !x.e.lease_active);
    }
    {   // door replaced: revalidation retires, lease gone
        Solo x;
        x.host();
        ++x.e.door_inc;
        x.c.tick(1050);
        CHECK(x.last().reason == Reason::Stale && !x.e.lease_active);
    }
    {   // cancel
        Solo x;
        x.host();
        x.c.receive(CancelMsg{x.f, 1});
        CHECK(!x.e.lease_active);
    }
}

TEST(r1356_lease_unavailable_or_refused_changes_nothing_else) {
    {
        Pair p;
        p.he.eligibility_cap = false;
        p.ge.eligibility_cap = false;
        p.intent();
        p.run();
        CHECK(p.he.lease_calls == 0 && p.hlast().phase == DoorPhase::OpenBoth);
        CHECK(p.hlast().facts.partner_eligible == Tri::Unknown);
    }
    {
        Pair p;
        p.he.lease_grants = false;
        p.intent();
        p.run();
        CHECK(p.he.lease_calls >= 1 && !p.he.lease_active && p.hlast().phase == DoorPhase::OpenBoth);
    }
}

TEST(r1356_no_free_slot_is_reported_not_hidden) {
    Pair p;
    p.he.report.no_free_slot = 5;   // both NPC slots held by real story NPCs
    p.intent();
    p.run();
    CHECK(p.hlast().facts.partner_eligible == Tri::False);
}

// ------------------------------------------------------------------ R1328 core-claims review: OpenBoth needs host proof
namespace {
// Guest whose own leaf visibly moves by itself (not follow-driven), so only the host's
// outcome decides whether "both" may be claimed.
struct MovingGuest {
    FakeEngine e;
    CaptureTransport t;
    CaptureJournal j;
    DoorCore c{e, t, j};
    Fence f = make_fence();
    MovingGuest() {
        c.receive(SessionMsg{f, Role::Guest, true, true, true});
        c.receive(SelectMsg{f, kDoorImpl});
        c.receive(ApplyMsg{f, 1, 1, kDoor, Side::B});
        c.tick(1000);
    }
    const OpView& last() const { static const OpView none{}; return c.finished().empty() ? none : c.finished().back(); }
};
}  // namespace

TEST(r1328c_guest_open_both_requires_an_affirmative_host_outcome) {
    {   // no host outcome at all: the deadline never invents success
        MovingGuest g;
        g.c.tick(1100);
        g.c.tick(8000);
        CHECK(g.last().facts.progress == Tri::True);
        CHECK(g.last().phase == DoorPhase::Uncertain && g.last().reason == Reason::GuestTimeout);
    }
    {   // host says its leaf did not progress
        MovingGuest g;
        g.c.receive(HostDoneMsg{g.f, 1, Tri::False, Tri::Unknown, Reason::None});
        g.c.tick(1100);
        g.c.tick(8000);
        CHECK(g.last().phase == DoorPhase::Mismatch && g.last().reason == Reason::NoProgress);
    }
    {   // host progress unknown with a failure reason
        MovingGuest g;
        g.c.receive(HostDoneMsg{g.f, 1, Tri::Unknown, Tri::Unknown, Reason::Disconnected});
        g.c.tick(1100);
        g.c.tick(8000);
        CHECK(g.last().phase == DoorPhase::Uncertain && g.last().reason == Reason::Disconnected);
    }
    {   // host progressed but reports a failure reason: not "both"
        MovingGuest g;
        g.c.receive(HostDoneMsg{g.f, 1, Tri::True, Tri::Unknown, Reason::ConsentLost});
        g.c.tick(1100);
        CHECK(g.last().phase == DoorPhase::Uncertain && g.last().reason == Reason::ConsentLost);
    }
    {   // affirmative host outcome for this op/fence: OpenBoth
        MovingGuest g;
        g.c.receive(HostDoneMsg{g.f, 1, Tri::True, Tri::Unknown, Reason::None});
        g.c.tick(1100);
        CHECK(g.last().phase == DoorPhase::OpenBoth);
    }
}

TEST(r1328c_moved_then_scene_needs_affirmative_host_proof) {
    {
        MovingGuest g;
        g.c.receive(HostDoneMsg{g.f, 1, Tri::Unknown, Tri::Unknown, Reason::None});
        Fence moved = g.f;
        moved.scene_room = 348;
        g.c.receive(SessionMsg{moved, Role::Guest, true, true, true});
        g.c.tick(1100);
        CHECK(g.last().phase != DoorPhase::OpenBoth);
    }
    {
        MovingGuest g;
        g.c.tick(1050);   // local motion established first
        g.c.receive(HostDoneMsg{g.f, 1, Tri::True, Tri::Unknown, Reason::None});
        Fence moved = g.f;
        moved.scene_room = 348;
        g.c.receive(SessionMsg{moved, Role::Guest, true, true, true});
        g.c.tick(1100);
        CHECK(g.last().phase == DoorPhase::OpenBoth);
    }
}

TEST(r1328c_first_host_outcome_stands) {
    MovingGuest g;
    g.c.receive(HostDoneMsg{g.f, 1, Tri::False, Tri::Unknown, Reason::None});
    g.c.receive(HostDoneMsg{g.f, 1, Tri::True, Tri::Unknown, Reason::None});   // a later contradicting copy
    g.c.tick(1100);
    g.c.tick(8000);
    CHECK(g.last().phase == DoorPhase::Mismatch && g.c.counters().duplicates >= 1);
}

// ------------------------------------------------------------------ R1414 static review: adapter mutation boundary
TEST(r1414s_authority_lost_during_adapter_final_reads_is_permit_denied_not_entered) {
    Solo x;
    bool once = false;
    x.e.in_final_reads = [&] {
        if (once) return;
        once = true;
        auto s = x.s(Role::Host);
        s.consent = false;
        x.c.receive(s);   // revocation arrives inside the adapter's last reads
    };
    x.host();
    CHECK(x.e.permit_denials == 1 && x.e.open_calls == 0);
    CHECK(x.last().phase == DoorPhase::Blocked && x.last().reason == Reason::NoConsent);
    CHECK(x.last().facts.engine_entered == Tri::Unknown && !x.e.lease_active && x.e.lease_calls == 0);
}

TEST(r1414s_guest_mirror_is_fenced_at_the_adapter_boundary_too) {
    Solo x;
    bool once = false;
    x.e.in_final_reads = [&] {
        if (once) return;
        once = true;
        auto s = x.s(Role::Guest);
        s.connected = false;
        x.c.receive(s);
    };
    x.guest();
    CHECK(x.e.permit_denials == 1 && x.e.mirror_calls == 0);
    CHECK(x.last().phase == DoorPhase::Blocked && x.last().reason == Reason::Disconnected);
}

TEST(r1414s_permit_is_pure_state_and_passes_when_authority_holds) {
    Solo x;
    x.host();
    CHECK(x.e.permit_denials == 0 && x.e.open_calls == 1 && x.c.active().has_value());
}

// ------------------------------------------------------------------ R1446 static review: retained lease authority
TEST(r1446s_lease_permit_is_the_exact_current_lease_and_pure_state) {
    Solo x;
    x.host();
    CHECK(x.e.lease_active);
    const int sample0 = x.e.sample_calls, lease0 = x.e.lease_calls;
    CHECK(x.c.lease_permit(x.e.lease_door, x.e.lease_actor));
    CHECK(!x.c.lease_permit(ObjRef{x.e.lease_door.token, x.e.lease_door.incarnation + 1}, x.e.lease_actor));   // another door incarnation
    CHECK(!x.c.lease_permit(x.e.lease_door, ObjRef{x.e.lease_actor.token, x.e.lease_actor.incarnation + 1}));   // another actor
    CHECK(!x.c.lease_permit(x.e.lease_actor, x.e.lease_door));
    CHECK(x.e.sample_calls == sample0 && x.e.lease_calls == lease0);   // no engine/bridge call
    auto s = x.s(Role::Host);
    s.playing = false;                                           // a hold, still only queued
    x.c.receive(s);
    CHECK(!x.c.lease_permit(x.e.lease_door, x.e.lease_actor) && !x.e.lease_active);
}

TEST(r1446s_no_operation_or_finished_operation_denies_the_hook) {
    Solo x;
    CHECK(!x.c.lease_permit(ObjRef{100, 1}, ObjRef{2, 1}));      // nothing active: never a healthy default
    x.host();
    ObjRef d = x.e.lease_door, a = x.e.lease_actor;
    x.c.receive(CancelMsg{x.f, 1});
    CHECK(!x.c.lease_permit(d, a));                              // cancelled: immediately, before the tick
    x.c.tick(1050);
    CHECK(!x.c.lease_permit(d, a) && !x.e.lease_active);
}

TEST(r1446s_known_overflow_denies_the_hook_and_ends_the_lease_before_any_tick) {
    Solo x;
    x.host();
    ObjRef d = x.e.lease_door, a = x.e.lease_actor;
    CHECK(x.c.lease_permit(d, a));
    for (int i = 0; i < 200 && x.c.counters().inbox_overflow == 0; ++i) x.c.receive(CancelMsg{x.f, 99});   // foreign op: queued
    CHECK(x.c.counters().inbox_overflow > 0);
    CHECK(!x.c.lease_permit(d, a) && !x.e.lease_active);         // no tick ran in between
}

TEST(r1446s_hook_revocation_is_reconciled_never_reported_healthy) {
    Solo x;
    x.host();
    CHECK(x.e.lease_active && x.e.lease_calls == 1);
    uint64_t now = 1050;
    for (int k = 1; k <= 2; ++k) {                               // the hook ends the lease between ticks
        x.e.lease_active = false;
        ++x.e.report.revoked_in_hook;
        x.c.tick(now);
        now += 50;
        CHECK(x.c.counters().leases_lost_in_hook == static_cast<uint64_t>(k));
        CHECK(x.e.lease_calls == 1 + k && x.e.lease_active);       // full revalidating re-grant, counted
    }
    x.e.lease_active = false;                                    // beyond the bound: retired, not renewed
    ++x.e.report.revoked_in_hook;
    x.c.tick(now);
    CHECK(x.c.counters().leases_lost_in_hook == 3 && x.c.counters().leases_retired == 1);
    CHECK(x.e.lease_calls == 3 && !x.e.lease_active && !x.c.lease_permit(x.e.lease_door, x.e.lease_actor));
    x.c.tick(now + 50);
    CHECK(x.e.lease_calls == 3 && x.c.active().has_value());     // the operation itself continues
}

TEST(r1446s_await_guest_hook_loss_is_reconciled_without_regrant) {
    Solo x;
    x.host();
    x.c.tick(1050);
    x.c.tick(7100);                                              // local deadline: host_done sent, waiting for the guest
    if (!x.j.has("host_local_done")) { CHECK(x.j.has("host_local_done")); return; }
    CHECK(x.c.active().has_value() && x.e.lease_active);
    const int lease0 = x.e.lease_calls;
    x.e.lease_active = false;                                    // the hook ends it while the host awaits the guest
    ++x.e.report.revoked_in_hook;
    x.c.tick(7150);
    CHECK(x.c.counters().leases_lost_in_hook == 1 && x.e.lease_calls == lease0);   // reconciled, never re-granted here
    CHECK(!x.c.lease_permit(x.e.lease_door, x.e.lease_actor));
}

TEST(r1446s_hook_fault_retires_the_lease_without_regrant) {
    Solo x;
    x.host();
    x.e.lease_active = false;
    ++x.e.report.hook_faults;
    ++x.e.report.revoked_in_hook;
    x.c.tick(1050);
    CHECK(x.c.counters().leases_retired == 1 && x.e.lease_calls == 1 && !x.e.lease_active);
    bool lost = false, retired = false;
    for (auto& r : x.j.records) {
        if (r.event == "eligibility_lease_lost" && r.detail == "hook_fault") lost = true;
        if (r.event == "eligibility_lease_retired") retired = true;
    }
    CHECK(lost && retired);
}

TEST(r1446s_abandon_lease_retires_now_and_nothing_regrants_it) {
    Solo x;
    x.host();
    ObjRef d = x.e.lease_door, a = x.e.lease_actor;
    const int rel0 = x.e.release_calls;
    x.c.abandon_lease();                                         // the embedder's callback boundary failed
    CHECK(!x.e.lease_active && x.e.release_calls > rel0 && !x.c.lease_permit(d, a));
    CHECK(x.c.counters().leases_retired == 1);
    x.c.tick(1050);                                              // even if a tick did run, no re-grant
    CHECK(x.e.lease_calls == 1 && !x.e.lease_active);
    Solo idle;
    idle.c.abandon_lease();                                      // no operation: a no-op
    CHECK(idle.e.release_calls == 0);
}

// ------------------------------------------------------------------ codec
TEST(codec_round_trips_every_message) {
    Fence f = make_fence();
    std::vector<Message> all = {
        SessionMsg{f, Role::Host, true, true, true},
        IntentMsg{f, 1, kDoor, ActorRole::P2},
        CancelMsg{f, 1},
        SelectMsg{f, kDoorImpl},
        SelectAckMsg{f, kDoorImpl, false, Reason::Unsupported},
        ApplyMsg{f, 1, 1, kDoor, Side::B},
        ProgressMsg{f, 1, 3, WireValue{7420, true}},
        HostDoneMsg{f, 1, Tri::True, Tri::Unknown, Reason::None},
        ResultMsg{f, 1, DoorPhase::OpenBoth, Reason::None, Tri::True, Tri::True},
        StatusMsg{f, 1, 1, Role::Guest, DoorPhase::Mismatch, Reason::DoorLocked},
        CapsMsg{true, 1, kDoorImpl},
    };
    for (auto& m : all) {
        std::string err;
        auto text = encode(m, &err);
        CHECK(text.has_value());
        if (!text) { std::printf("    encode %s: %s\n", type_name(m), err.c_str()); continue; }
        CHECK(text->size() <= kMaxMessageBytes);
        auto back = decode(*text, &err);
        CHECK(back.has_value());
        if (back) CHECK(encode(*back) == text);
        if (!back) std::printf("    %s: %s\n", text->c_str(), err.c_str());
    }
}

TEST(codec_maximum_identities_fit_the_bound) {
    Fence f{std::string(kMaxToken, 'c'), std::string(kMaxToken, 'b'), std::string(kMaxBoot, 'h'), std::string(kMaxBoot, 'g'),
            4294967295u, 4294967295u};
    DoorKey d{std::string(kMaxDoorName, 'd'), 4294967295u, 4294967295u};
    std::vector<Message> big = {
        ApplyMsg{f, 9007199254740991ull, 9007199254740991ull, d, Side::A},
        SelectAckMsg{f, kDoorImpl, true, Reason::NoOpenMutation},
        StatusMsg{f, 9007199254740991ull, 9007199254740991ull, Role::Guest, DoorPhase::OpenBothPartnerCrossedHost, Reason::ConsentLost},
        ProgressMsg{f, 9007199254740991ull, 1000, WireValue{kMaxValueMilli, true}},
        IntentMsg{f, 9007199254740991ull, d, ActorRole::P2},
    };
    size_t longest = 0;
    for (auto& m : big) {
        auto text = encode(m);
        CHECK(text.has_value());
        if (text) { longest = std::max(longest, text->size()); CHECK(text->size() <= kMaxMessageBytes); CHECK(decode(*text).has_value()); }
    }
    std::printf("    longest maximal message: %zu bytes (bound %zu)\n", longest, kMaxMessageBytes);
}

TEST(encode_refuses_invalid_actionable_values) {
    Fence f = make_fence();
    CHECK(!encode(ApplyMsg{f, 1, 1, kDoor, Side::Unknown}).has_value());
    CHECK(!encode(ApplyMsg{f, 1, 1, kDoor, static_cast<Side>(99)}).has_value());
    CHECK(!encode(IntentMsg{f, 1, kDoor, static_cast<ActorRole>(255)}).has_value());
    CHECK(!encode(ApplyMsg{f, 0, 1, kDoor, Side::A}).has_value());
    Fence bad = f; bad.connection = "";
    CHECK(!encode(ApplyMsg{bad, 1, 1, kDoor, Side::A}).has_value());
    bad = f; bad.barrier = std::string(kMaxToken + 1, 'x');
    CHECK(!encode(CancelMsg{bad, 1}).has_value());
    bad = f; bad.host_boot = "boot with space";
    CHECK(!encode(CancelMsg{bad, 1}).has_value());
    bad = f; bad.guest_boot = "q\"uote";
    CHECK(!encode(CancelMsg{bad, 1}).has_value());
    DoorKey d = kDoor; d.name = std::string(kMaxDoorName + 1, 'd');
    CHECK(!encode(IntentMsg{f, 1, d, ActorRole::P2}).has_value());
    CHECK(!encode(StatusMsg{f, 0, 0, Role::Host, static_cast<DoorPhase>(200), Reason::None}).has_value());
    CHECK(!encode(StatusMsg{f, 0, 0, Role::Host, DoorPhase::None, static_cast<Reason>(250)}).has_value());
    CHECK(!encode(StatusMsg{f, 0, 0, static_cast<Role>(9), DoorPhase::None, Reason::None}).has_value());
    CHECK(!encode(ResultMsg{f, 1, DoorPhase::OpenBoth, Reason::None, static_cast<Tri>(7), Tri::True}).has_value());
    CHECK(!encode(ProgressMsg{f, 1, 0, WireValue{1, false}}).has_value());
    CHECK(!encode(ProgressMsg{f, 1, 1, WireValue{kMaxValueMilli + 1, false}}).has_value());
    CHECK(!WireValue::from(std::nanf("")).has_value());
    CHECK(!WireValue::from(1000.5f).has_value());
    CHECK(WireValue::from(-0.0004f).has_value() && !WireValue::from(-0.0004f)->negative);
}

TEST(codec_rejects_contract_violations) {
    std::string F = R"("conn":"c-1","bar":"b-1","hb":"h1","gb":"g1","loc":23,"room":347)";
    std::vector<std::string> bad = {
        R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":1,"extra":1})",
        R"({"v":1,"t":"door_cancel",)" + F + R"(})",
        R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":"1"})",
        R"({"v":1,"t":"door_progress",)" + F + R"(,"op":1,"n":1,"vmil":0.5,"vneg":false})",
        R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":-1})",
        R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":1,"op":2})",
        R"({"v":2,"t":"door_cancel",)" + F + R"(,"op":1})",
        R"({"v":1,"t":"door_progress",)" + F + R"(,"op":1,"n":1,"vmil":1000001,"vneg":false})",
        R"({"v":1,"t":"door_apply",)" + F + R"(,"op":1,"req":1,"door":"d","dloc":1,"droom":1,"side":"unknown"})",
        R"({"v":1,"t":"door_apply",)" + F + R"(,"op":1,"req":1,"door":"d","dloc":1,"droom":1,"side":"c"})",
        R"({"v":1,"t":"door_intent",)" + F + R"(,"req":1,"door":"a b","dloc":23,"droom":347,"actor":"p2"})",
        R"({"v":1,"t":"door_intent",)" + F + R"(,"req":1,"door":"d","dloc":23,"droom":347,"actor":"p3"})",
        R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":1} x)",
        R"({"v":1,"t":"door_cancel","conn":"","bar":"b","hb":"h","gb":"g","loc":1,"room":1,"op":1})",
        R"({"v":1,"t":"nope"})",
        R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":01})",
        R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":9007199254740992})",
        R"({"v":1,"t":"door_select",)" + F + R"(,"impl":"door native"})",
        R"([1,2])",
        "",
    };
    for (auto& t : bad) {
        bool rejected = !decode(t).has_value();
        if (!rejected) std::printf("    accepted: %s\n", t.c_str());
        CHECK(rejected);
    }
    CHECK(!decode(R"({"v":1,"t":"door_cancel",)" + F + R"(,"op":1)" + std::string(1100, ' ') + "}").has_value());
}

TEST(journal_lines_are_bounded_and_escaped) {
    JournalRecord r;
    r.event = "final";
    r.connection = kConn;
    r.detail = std::string(300, 'x') + "\"\\";
    std::string line = journal_line(r);
    CHECK(line.find('\\') == std::string::npos && line.size() < 600);
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    for (auto& t : reg()) {
        g_test = t.name;
        int before = g_fail;
        std::printf("RUN  %s\n", t.name);
        t.fn();
        std::printf("%s %s\n", g_fail == before ? "PASS" : "FAIL", t.name);
    }
    std::printf("tests=%zu checks=%d failures=%d\n", reg().size(), g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
