// Offline adapter tests (R1328): the exact plugin channel pump against a fake channel,
// and a loopback self-test of the real LocalChannel worker inside this test process.
// No game, SDK, loader or DLL is involved; the loopback pipe is private to this process
// (unique name, current-user DACL, remote clients rejected) and closed at exit.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include "channel_pump.hpp"
#include "engine_callback.hpp"
#include "fakes.hpp"
#include "pipe_transport.hpp"

using namespace re2net;
using namespace re2net::core;
using namespace re2net::test;
using re2net::adapter::InFrame;

namespace {
int g_fail = 0, g_checks = 0;
std::string g_test;
struct Reg { const char* name; void (*fn)(); };
std::vector<Reg>& reg() { static std::vector<Reg> r; return r; }
}  // namespace
#define CHECK(c) do { ++g_checks; if (!(c)) { ++g_fail; std::printf("  FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, g_test.c_str(), #c); } } while (0)
#define TEST(n) static void n(); static int n##_reg = (reg().push_back({#n, n}), 0); static void n()

namespace {
const Fence F{"3f0c5e8a-6b1d-4c2e-9a7f-1d2e3f4a5b6c:8d7e6f5a-4b3c-4d2e-8f1a-0b9c8d7e6f5a", "barrier-1", "hb1", "gb1", 23, 347};
const DoorKey D{"GasStation_ConvenienceDoor01A_gimmick", 23, 347};

struct FakeChannel {
    uint64_t epoch = 1;
    bool up = true, fail = false;
    std::vector<InFrame> frames;
    std::vector<uint64_t> dropped;
    uint64_t connection_epoch() const { return epoch; }
    bool connected() const { return up; }
    bool failed() const { return fail; }
    std::function<void()> after_take;   // the worker moving on after take_in released its lock
    std::vector<InFrame> take_in() { auto x = frames; frames.clear(); if (after_take) after_take(); return x; }
    void drop_client(uint64_t e) { dropped.push_back(e); }   // the real worker acts on this later
    void push(uint64_t e, const Message& m) { frames.push_back(InFrame{e, *encode(m)}); }
    void bad(uint64_t e) { frames.push_back(InFrame{e, "{\"v\":1,\"t\":\"session\"}"}); }
};

struct Rig {
    FakeEngine e;
    CaptureTransport t;
    CaptureJournal j;
    DoorCore core{e, t, j};
    FakeChannel ch;
    adapter::ChannelPump<FakeChannel> pump;
    Rig() { core.set_local_fence([this] { return pump.live(ch); }); }   // exactly as plugin_main installs it
    void step(uint64_t now) { pump.step(ch, core, t, now); }
    // Host with fresh session + completed handshake on local connection `ep`.
    void selected_host(uint64_t ep) {
        ch.epoch = ep;
        ch.push(ep, SessionMsg{F, Role::Host, true, true, true});
        step(1000);
        ch.push(ep, SelectAckMsg{F, kDoorImpl, true, Reason::None});
        step(1050);
    }
    size_t caps_sent() const { return t.of<CapsMsg>().size(); }
};
}  // namespace

// ------------------------------------------------------------------ pump (pipe review 1328 finding 1)
TEST(pump_fast_reconnect_requires_fresh_session) {   // the review's failing case
    Rig r;
    r.selected_host(1);
    CHECK(r.core.selected());
    r.ch.epoch = 3;                                    // 1 -> 2 (unseen disconnect) -> 3, connected again
    r.ch.push(3, IntentMsg{F, 1, D, ActorRole::P2});   // old-fence intent from the NEW client, no session
    r.step(2000);
    CHECK(r.e.open_calls == 0);
    CHECK(!r.core.selected() && !r.core.session().connected);
    CHECK(r.caps_sent() == 2);                          // caps first on each adopted connection
    CHECK(r.pump.resets == 2);
}

TEST(pump_initial_connect_without_session_blocks) {
    Rig r;
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(1000);
    CHECK(r.e.open_calls == 0);
}

TEST(pump_visible_disconnect_reaches_core) {
    Rig r;
    r.selected_host(1);
    r.ch.epoch = 2;
    r.ch.up = false;
    r.step(2000);
    CHECK(!r.core.session().connected && r.caps_sent() == 1);
}

TEST(pump_frames_of_an_older_connection_are_discarded) {
    Rig r;
    r.selected_host(3);
    r.ch.push(1, SessionMsg{F, Role::Host, true, true, true});
    r.ch.push(2, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(2000);
    CHECK(r.pump.stale_frames == 2 && r.e.open_calls == 0 && r.core.active() == std::nullopt);
}

// R1328 replacement of pump_frame_from_a_newer_connection_adopts_it_first: a frame is
// accepted only if its connection is the live one when re-read after the snapshot.
TEST(pump_snapshot_frame_of_the_current_newer_connection_is_adopted_after_reset) {
    Rig r;
    r.selected_host(1);
    r.ch.push(3, IntentMsg{F, 1, D, ActorRole::P2});
    r.ch.after_take = [&] { r.ch.epoch = 3; };         // the new client is the live connection after take
    r.step(2000);
    CHECK(r.pump.seen_epoch == 3 && r.pump.late_epoch_changes == 1);
    CHECK(r.e.open_calls == 0 && !r.core.session().connected);   // still needs a fresh session
}

TEST(pump_frame_newer_than_the_sample_is_discarded_if_the_channel_moved_beyond_it) {
    Rig r;
    r.selected_host(1);
    r.ch.push(3, SessionMsg{F, Role::Host, true, true, true});
    r.ch.after_take = [&] { r.ch.epoch = 5; };         // epoch 3's client is already gone again
    r.step(2000);
    CHECK(r.pump.seen_epoch == 5 && r.pump.stale_frames == 1 && !r.core.session().connected);
}

// ------------------------------------------------------------------ R1328 independent review regressions
TEST(r1328i_bad_epoch_cannot_regrant_host_in_same_batch) {
    Rig r;
    r.selected_host(1);
    r.ch.bad(1);
    r.ch.push(1, SessionMsg{F, Role::Host, true, true, true});
    r.ch.push(1, SelectAckMsg{F, kDoorImpl, true, Reason::None});
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(2000);
    CHECK(r.e.open_calls == 0 && !r.core.session().connected && !r.core.selected());
    CHECK(r.pump.poisoned_epoch == 1 && r.pump.poisoned_frames == 3 && r.ch.dropped.size() == 1);
    CHECK(r.core.legacy_reserved());   // no fallback on ambiguity
}

TEST(r1328i_bad_epoch_cannot_regrant_guest_in_same_batch) {
    Rig r;
    r.e.follow_driven_only = true;
    r.ch.bad(1);
    r.ch.push(1, SessionMsg{F, Role::Guest, true, true, true});
    r.ch.push(1, SelectMsg{F, kDoorImpl});
    r.ch.push(1, ApplyMsg{F, 1, 1, D, Side::B});
    r.step(2000);
    CHECK(r.e.mirror_calls == 0 && !r.core.session().connected && !r.core.selected());
}

TEST(r1328i_bad_epoch_cannot_regrant_before_the_worker_acts_on_the_drop) {
    Rig r;
    r.selected_host(1);
    r.ch.bad(1);
    r.step(2000);
    r.ch.push(1, SessionMsg{F, Role::Host, true, true, true});   // same epoch: the worker has not disconnected yet
    r.ch.push(1, SelectAckMsg{F, kDoorImpl, true, Reason::None});
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(2050);
    r.step(2100);
    CHECK(r.e.open_calls == 0 && !r.core.session().connected);
    CHECK(!r.pump.live(r.ch));
}

TEST(r1328i_poison_ends_only_at_a_strictly_newer_real_epoch) {
    Rig r;
    r.selected_host(1);
    r.ch.bad(1);
    r.step(2000);
    size_t caps_before = r.caps_sent();
    r.ch.epoch = 3;                                                // the worker dropped and a client reconnected
    r.step(2050);
    CHECK(r.caps_sent() == caps_before + 1 && r.pump.live(r.ch));
    r.selected_host(3);
    r.ch.push(3, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(3000);
    CHECK(r.e.open_calls == 1);
}

TEST(r1328i_core_inbox_loss_poisons_the_epoch) {
    Rig r;
    r.selected_host(1);
    for (int i = 0; i < 40; ++i) r.ch.push(1, CancelMsg{F, 99});   // more than the core inbox holds
    r.step(2000);
    r.ch.push(1, SessionMsg{F, Role::Host, true, true, true});
    r.ch.push(1, SelectAckMsg{F, kDoorImpl, true, Reason::None});
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(2050);
    CHECK(r.pump.poisoned_epoch == 1 && r.e.open_calls == 0 && !r.core.session().connected);
}

TEST(r1328i_epoch_change_after_take_cannot_execute_old_snapshot) {
    Rig r;
    r.selected_host(1);
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    r.ch.after_take = [&] { r.ch.epoch = 3; };
    r.step(2000);
    CHECK(r.e.open_calls == 0 && !r.core.session().connected && r.pump.stale_frames == 1);
}

TEST(r1328i_engine_entry_is_fenced_against_the_live_local_connection) {
    Rig r;
    r.selected_host(1);
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    bool once = false;
    r.e.in_sample = [&] { if (!once) { once = true; r.ch.epoch = 3; } };   // channel moves inside the admission read
    r.step(2000);
    CHECK(r.e.open_calls == 0);
    CHECK(!r.core.finished().empty() && r.core.finished().back().phase == DoorPhase::Blocked &&
          r.core.finished().back().reason == Reason::Disconnected);
}

TEST(r1414s_local_connection_lost_during_adapter_final_reads_is_permit_denied) {
    Rig r;
    r.selected_host(1);
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    bool once = false;
    r.e.in_final_reads = [&] { if (!once) { once = true; r.ch.epoch = 3; } };   // worker moved after the core's last check
    r.step(2000);
    CHECK(r.e.permit_denials == 1 && r.e.open_calls == 0);
    CHECK(r.core.finished().back().phase == DoorPhase::Blocked && r.core.finished().back().reason == Reason::Disconnected);
}

TEST(r1328i_fence_retires_an_open_operation_and_its_lease) {
    Rig r;
    r.selected_host(1);
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(2000);
    CHECK(r.e.open_calls == 1 && r.e.lease_active);
    r.e.in_sample = [&] { r.ch.up = false; };   // the worker publishes a disconnect during observation
    r.step(2050);
    CHECK(r.core.finished().back().phase == DoorPhase::Interrupted &&
          r.core.finished().back().reason == Reason::Disconnected && !r.e.lease_active);
}

// ------------------------------------------------------------------ R1446 static review: retained hook authority
// The plugin's exact hook permit and callback boundary (engine_callback.hpp, compiled into
// plugin_main.cpp too) over the real pump and core. `hook()` is what the bridge's
// hook_permit_now() asks for the leased refs.
namespace {
struct PluginRig : Rig {
    bool blocked = false;
    bool owner = true;   // the callback ran on the engine owner thread
    int bodies = 0;
    bool hook() const { return adapter::retained_hook_permit(blocked, &core, e.lease_door, e.lease_actor); }
    template <class Body> void callback(Body&& body) {
        adapter::run_engine_callback(blocked, &core, [this] { return owner; }, [&] { ++bodies; body(); });
    }
    void open(uint64_t now) {
        selected_host(1);
        ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
        callback([&] { step(now); });
    }
};
}  // namespace

TEST(r1446s_throw_after_grant_blocks_and_retires_the_lease_now) {
    PluginRig r;
    r.open(2000);
    CHECK(r.e.open_calls == 1 && r.e.lease_active && r.hook());
    const int rel0 = r.e.release_calls;
    r.callback([&] { r.step(2050); throw std::runtime_error("counters journal allocation"); });   // after the core's tick
    CHECK(r.blocked && !r.e.lease_active && r.e.release_calls > rel0);
    CHECK(!r.hook());                                            // the channel is still live: not enough
    CHECK(r.ch.connected() && r.pump.live(r.ch));
    const int bodies = r.bodies;
    r.callback([&] { r.step(2100); });                           // blocked: later callbacks return at once
    CHECK(r.bodies == bodies && !r.e.lease_active && r.e.lease_calls == 1);
}

TEST(r1446s_throw_off_the_owner_thread_cleans_nothing_but_still_refuses_the_hook) {
    PluginRig r;
    r.open(2000);
    const int rel0 = r.e.release_calls;
    r.owner = false;
    r.callback([] { throw std::runtime_error("foreign"); });
    CHECK(r.blocked && r.e.release_calls == rel0);              // no cleanup off the owner thread
    CHECK(!r.hook());                                            // blocked alone refuses every hook
}

TEST(r1446s_block_without_throw_refuses_the_hook) {
    PluginRig r;
    r.open(2000);
    CHECK(r.hook());
    r.blocked = true;                                            // e.g. callback registration refused
    CHECK(!r.hook());
}

TEST(r1446s_hook_permit_follows_the_epoch_between_callbacks) {
    PluginRig r;
    r.open(2000);
    CHECK(r.hook());
    r.ch.epoch = 3;                                              // the worker moved on; no LateUpdate yet
    CHECK(!r.hook());
}

TEST(r1446s_hook_permit_follows_known_overflow_and_the_exact_lease) {
    PluginRig r;
    r.open(2000);
    CHECK(r.hook());
    CHECK(!adapter::retained_hook_permit(r.blocked, &r.core, r.e.lease_door, ObjRef{2, r.e.lease_actor.incarnation + 1}));
    CHECK(!adapter::retained_hook_permit(r.blocked, static_cast<const DoorCore*>(nullptr), r.e.lease_door, r.e.lease_actor));
    for (int i = 0; i < 200 && r.core.counters().inbox_overflow == 0; ++i) r.core.receive(CancelMsg{F, 99});
    CHECK(r.core.counters().inbox_overflow > 0 && !r.hook() && !r.e.lease_active);   // before any pump/tick
}

TEST(pump_fresh_session_on_new_connection_restores_operation) {
    Rig r;
    r.selected_host(1);
    r.ch.epoch = 3;
    r.step(1500);
    r.selected_host(3);
    r.ch.push(3, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(2000);
    CHECK(r.e.open_calls == 1 && r.core.active().has_value());
}

TEST(pump_undecodable_frame_drops_that_client) {
    Rig r;
    r.selected_host(1);
    r.ch.frames.push_back(InFrame{1, "{\"v\":1,\"t\":\"session\"}"});
    r.step(2000);
    CHECK(r.pump.rejected_text == 1 && r.ch.dropped.size() == 1 && r.ch.dropped[0] == 1);
    CHECK(!r.core.session().connected);
}

TEST(pump_core_inbox_overflow_drops_the_client) {
    Rig r;
    r.selected_host(1);
    for (int i = 0; i < 40; ++i) r.ch.push(1, CancelMsg{F, 99});
    r.step(2000);
    CHECK(r.ch.dropped.size() == 1 && r.core.counters().inbox_overflow > 0);
}

TEST(pump_worker_failure_resets_once_and_stops_reading) {
    Rig r;
    r.selected_host(1);
    r.ch.fail = true;
    r.ch.push(1, IntentMsg{F, 1, D, ActorRole::P2});
    r.step(2000);
    r.step(2050);
    CHECK(r.pump.resets == 2 && r.e.open_calls == 0 && !r.core.session().connected);
}

// ------------------------------------------------------------------ LocalChannel loopback (pipe findings 1-6)
namespace {
struct Client {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit Client(const std::wstring& name) {
        for (int i = 0; i < 100 && h == INVALID_HANDLE_VALUE; ++i) {
            h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (h == INVALID_HANDLE_VALUE) { WaitNamedPipeW(name.c_str(), 50); Sleep(10); }
        }
    }
    ~Client() { close(); }
    void close() { if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; } }
    bool write(const std::string& s) {
        DWORD w = 0;
        return h != INVALID_HANDLE_VALUE && WriteFile(h, s.data(), static_cast<DWORD>(s.size()), &w, nullptr) && w == s.size();
    }
    // Reads whatever arrives within `ms`; sets broken when the server end went away.
    std::string read_for(int ms, bool* broken = nullptr) {
        std::string out;
        auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < until) {
            DWORD avail = 0;
            if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr)) { if (broken) *broken = true; break; }
            if (avail) {
                std::string buf(avail, '\0');
                DWORD n = 0;
                if (ReadFile(h, buf.data(), avail, &n, nullptr)) out.append(buf.data(), n);
            } else {
                Sleep(5);
            }
        }
        return out;
    }
};

template <class Pred> bool wait_until(Pred p, int ms = 2000) {
    auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < until) { if (p()) return true; Sleep(5); }
    return p();
}

std::wstring pipe_name(const wchar_t* tag) {
    return L"\\\\.\\pipe\\re2net-door-selftest-" + std::to_wstring(GetCurrentProcessId()) + L"-" + tag;
}
std::wstring journal_name(const wchar_t* tag) { return std::wstring(L"channel-selftest-") + tag + L".jsonl"; }

double process_cpu_ms() {
    FILETIME c, e, k, u;
    GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
    auto v = [](FILETIME f) { return (static_cast<uint64_t>(f.dwHighDateTime) << 32 | f.dwLowDateTime) / 10000.0; };
    return v(k) + v(u);
}
}  // namespace

TEST(channel_frames_are_tagged_and_outbound_bound_to_the_live_connection) {
    adapter::LocalChannel ch;
    std::string why;
    auto name = pipe_name(L"tags");
    CHECK(ch.start(name, journal_name(L"tags"), why));
    Client c(name);
    CHECK(wait_until([&] { return ch.connected(); }));
    uint64_t e1 = ch.connection_epoch();
    CHECK(c.write("hello\n"));
    std::vector<InFrame> in;
    CHECK(wait_until([&] { auto v = ch.take_in(); in.insert(in.end(), v.begin(), v.end()); return !in.empty(); }));
    CHECK(in.size() == 1 && in[0].line == "hello" && in[0].epoch == e1);
    CHECK(ch.push_out("{\"x\":1}", e1));
    CHECK(c.read_for(300) == "{\"x\":1}\n");
    CHECK(!ch.push_out("{\"x\":2}", e1 + 7));           // not the live connection
    c.close();
    CHECK(wait_until([&] { return !ch.connected(); }));
    CHECK(ch.connection_epoch() > e1);
    CHECK(!ch.push_out("{\"x\":3}", e1));               // the old connection is gone: refused, never queued
    Client c2(name);
    CHECK(wait_until([&] { return ch.connected(); }));
    uint64_t e3 = ch.connection_epoch();
    CHECK(e3 > e1 + 1);
    CHECK(c2.read_for(200).empty());                     // nothing of the old connection reaches the new client
    CHECK(c2.write("again\n"));
    in.clear();
    CHECK(wait_until([&] { auto v = ch.take_in(); in.insert(in.end(), v.begin(), v.end()); return !in.empty(); }));
    CHECK(in.size() == 1 && in[0].epoch == e3);
}

TEST(channel_oversize_line_is_an_explicit_loss_and_disconnect) {
    adapter::LocalChannel ch;
    std::string why;
    auto name = pipe_name(L"oversize");
    CHECK(ch.start(name, journal_name(L"oversize"), why));
    Client c(name);
    CHECK(wait_until([&] { return ch.connected(); }));
    uint64_t e1 = ch.connection_epoch();
    c.write(std::string(1100, 'x') + "\n");
    CHECK(wait_until([&] { return ch.connection_epoch() > e1; }));
    auto k = ch.counters();
    CHECK(k.oversize == 1 && k.loss_disconnects == 1);
}

TEST(channel_inbound_full_is_an_explicit_loss_and_disconnect) {
    adapter::LocalChannel ch;
    std::string why;
    auto name = pipe_name(L"full");
    CHECK(ch.start(name, journal_name(L"full"), why));
    Client c(name);
    CHECK(wait_until([&] { return ch.connected(); }));
    uint64_t e1 = ch.connection_epoch();
    std::string burst;
    for (size_t i = 0; i < adapter::LocalChannel::kInCap + 6; ++i) burst += "line\n";
    c.write(burst);                                      // nobody takes: the queue fills
    CHECK(wait_until([&] { return ch.connection_epoch() > e1; }));
    auto k = ch.counters();
    CHECK(k.in_dropped == 1 && k.loss_disconnects == 1);
    CHECK(ch.take_in().empty());                         // the lost connection's queued frames are gone too
}

TEST(channel_drop_client_forces_a_new_connection) {
    adapter::LocalChannel ch;
    std::string why;
    auto name = pipe_name(L"drop");
    CHECK(ch.start(name, journal_name(L"drop"), why));
    Client c(name);
    CHECK(wait_until([&] { return ch.connected(); }));
    uint64_t e1 = ch.connection_epoch();
    ch.drop_client(e1 + 5);                              // a stale request is ignored
    Sleep(100);
    CHECK(ch.connected() && ch.connection_epoch() == e1);
    ch.drop_client(e1);
    bool broken = false;
    CHECK(wait_until([&] { return ch.connection_epoch() > e1; }));
    c.read_for(100, &broken);
    CHECK(broken);
}

TEST(channel_idle_worker_does_not_spin) {
    adapter::LocalChannel ch;
    std::string why;
    auto name = pipe_name(L"idle");
    CHECK(ch.start(name, journal_name(L"idle"), why));
    Client c(name);
    CHECK(wait_until([&] { return ch.connected(); }));
    CHECK(ch.push_out("{\"x\":1}", ch.connection_epoch()));   // one completed write leaves its event consumed
    CHECK(c.read_for(200) == "{\"x\":1}\n");
    double cpu0 = process_cpu_ms();
    Sleep(1000);
    double used = process_cpu_ms() - cpu0;
    std::printf("    idle cpu over 1000 ms: %.1f ms\n", used);
    CHECK(used < 100.0);
}

TEST(channel_stop_drains_pending_io_before_teardown) {
    auto name = pipe_name(L"stop");
    double ms = 0;
    adapter::ChannelCounters k{};
    bool failed = true;
    {
        Client* c = nullptr;
        auto ch = std::make_unique<adapter::LocalChannel>();
        std::string why;
        CHECK(ch->start(name, journal_name(L"stop"), why));
        c = new Client(name);
        CHECK(wait_until([&] { return ch->connected(); }));   // a read is now pending in the worker
        ch->push_journal("{\"event\":\"selftest\"}");
        auto t0 = std::chrono::steady_clock::now();
        ch->request_stop();
        CHECK(wait_until([&] { return !ch->connected(); }));
        k = ch->counters();
        failed = ch->failed();
        ch.reset();                                    // joins the worker
        ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        delete c;
    }
    std::printf("    stop+join: %.1f ms\n", ms);
    CHECK(!failed && k.undrained == 0 && ms < 3000.0);
}

TEST(channel_journal_lines_are_bounded) {
    adapter::LocalChannel ch;
    std::string why;
    auto name = pipe_name(L"journal");
    CHECK(ch.start(name, journal_name(L"journal"), why));
    CHECK(!ch.push_journal(std::string(adapter::LocalChannel::kMaxJournalLine + 1, 'j')));
    CHECK(ch.push_journal("{\"event\":\"ok\"}"));
    CHECK(wait_until([&] { return ch.counters().journal_lines >= 1; }));
    CHECK(ch.counters().journal_dropped == 1);
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
