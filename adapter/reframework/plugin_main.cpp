// re2net native door plugin: REFramework bootstrap for the engine-independent core.
// Replaceable adapter; the core never sees REFramework types.
//
// Plugin lifecycle:
//  - Exact executable gate first: the running image's SHA-256 must equal the reviewed
//    re2.exe; otherwise initialize returns false before anything is allocated or started.
//  - Every throwing allocation (bridge preflight, core, names) happens before the
//    channel worker starts. initialize returns false only while no worker exists and
//    nothing is registered. From the moment the worker exists `g` owns it and stays
//    resident (intentionally leaked): later failures become a blocked state, never an
//    unload with a live worker.
//  - Every exception is contained at exported and callback boundaries. No native call
//    in DllMain; the channel worker does I/O only.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "channel_pump.hpp"
#include "engine_callback.hpp"
#include "pipe_transport.hpp"
#include "re_engine_bridge.hpp"
#include "re2net/core/door_core.hpp"

#pragma comment(lib, "bcrypt.lib")

using namespace re2net;

namespace {

// The exact executable digest required by this adapter.
constexpr const char* kReviewedExeSha256 = "6caaa815bf9e95f8a841bc81fdf29fec55e836c87bab8a76d55c69bef9ada941";

struct Plugin;
Plugin* g = nullptr;   // intentionally leaked once the worker exists: never destroyed while it may run

class ChannelTransport final : public core::Transport {
public:
    ChannelTransport(adapter::LocalChannel& ch, const uint64_t& epoch) : ch_(ch), epoch_(epoch) {}
    bool send(const core::Message& m) override {
        auto text = core::encode(m);
        return text && ch_.push_out(*text, epoch_);   // only to the local connection the pump adopted
    }
private:
    adapter::LocalChannel& ch_;
    const uint64_t& epoch_;
};

class ChannelJournal final : public core::Journal {
public:
    explicit ChannelJournal(adapter::LocalChannel& ch) : ch_(ch) {}
    void write(const core::JournalRecord& r) override { ch_.push_journal(core::journal_line(r)); }
private:
    adapter::LocalChannel& ch_;
};

struct Plugin {
    adapter::ReEngineBridge bridge;
    adapter::LocalChannel channel;
    adapter::ChannelPump<adapter::LocalChannel> pump;
    ChannelTransport transport{channel, pump.seen_epoch};
    ChannelJournal journal{channel};
    std::unique_ptr<core::DoorCore> core;
    const REFrameworkPluginFunctions* fns = nullptr;
    REFrameworkMethodHandle hooked = nullptr;
    unsigned int hook_id = 0;
    bool blocked = false;
    bool fault_reported = false;
    uint64_t last_counters_ms = 0;
    DWORD engine_tid = 0;
};

int on_opened_pre(int argc, void** argv, REFrameworkTypeDefinitionHandle*, unsigned long long) {
    adapter::ReEngineBridge::on_opened_witnessed(argc, argv);   // attribution only; no engine call
    return REFRAMEWORK_HOOK_CALL_ORIGINAL;
}
void on_opened_post(void**, REFrameworkTypeDefinitionHandle, unsigned long long) {}

// Door-scoped eligibility: scope = the door's own candidate consumers; the list builder
// is changed only inside the leased door's scope (ReEngineBridge::on_candidates_built).
// The bridge entries are noexcept with their own fail-closed boundaries; these C
// wrappers add nothing that can throw.
int door_scope_pre(int argc, void** argv, REFrameworkTypeDefinitionHandle*, unsigned long long) {
    adapter::ReEngineBridge::on_door_scope_enter(argc, argv);
    return REFRAMEWORK_HOOK_CALL_ORIGINAL;
}
void door_scope_post(void**, REFrameworkTypeDefinitionHandle, unsigned long long) {
    adapter::ReEngineBridge::on_door_scope_exit();
}
int candidates_pre(int, void**, REFrameworkTypeDefinitionHandle*, unsigned long long) { return REFRAMEWORK_HOOK_CALL_ORIGINAL; }
void candidates_post(void** ret_val, REFrameworkTypeDefinitionHandle, unsigned long long) {
    adapter::ReEngineBridge::on_candidates_built(ret_val);
}

uint64_t now_ms() { return GetTickCount64(); }

void journal_channel_counters(uint64_t now) {
    auto c = g->channel.counters();
    std::string line = "{\"ms\":" + std::to_string(now) + ",\"src\":\"plugin\",\"event\":\"channel_counters\"" +
                       ",\"frames_in\":" + std::to_string(c.frames_in) + ",\"frames_out\":" + std::to_string(c.frames_out) +
                       ",\"in_dropped\":" + std::to_string(c.in_dropped) + ",\"oversize\":" + std::to_string(c.oversize) +
                       ",\"loss_disconnects\":" + std::to_string(c.loss_disconnects) +
                       ",\"out_refused\":" + std::to_string(c.out_refused) +
                       ",\"journal_dropped\":" + std::to_string(c.journal_dropped) +
                       ",\"journal_errors\":" + std::to_string(c.journal_errors) +
                       ",\"undrained\":" + std::to_string(c.undrained) +
                       ",\"stale_frames\":" + std::to_string(g->pump.stale_frames) +
                       ",\"local_resets\":" + std::to_string(g->pump.resets) +
                       ",\"rejected_text\":" + std::to_string(g->pump.rejected_text) +
                       ",\"worker_failed\":" + (g->channel.failed() ? "true" : "false") + "}";
    g->channel.push_journal(line);
}

// A throw anywhere below (pump, caps send, counters journal) blocks the plugin and, on the
// engine thread, retires the core's lease immediately (R1446 static review finding 3): the
// retained hooks also refuse through `blocked` in their permit, never via a future tick.
void on_late_update() {
    if (!g) return;
    adapter::run_engine_callback(
        g->blocked, g->core.get(), [] { return g->engine_tid != 0 && GetCurrentThreadId() == g->engine_tid; }, [] {
            DWORD tid = GetCurrentThreadId();
            if (g->engine_tid == 0) {
                g->engine_tid = tid;
                adapter::ReEngineBridge::set_engine_thread(std::this_thread::get_id());   // hooks/leases bind to it
            }
            if (tid != g->engine_tid) return;   // only the one engine thread drives the core

            adapter::ReEngineBridge::begin_frame();   // door updates of this frame have completed
            uint64_t now = now_ms();
            g->pump.step(g->channel, *g->core, g->transport, now);   // epoch -> authority, frames, tick
            if (g->core->faulted() && !g->fault_reported && g->channel.connected()) {
                g->fault_reported = g->transport.send(g->core->caps());   // caps now report impl "none"
            }
            if (now - g->last_counters_ms >= 10000) {
                g->last_counters_ms = now;
                journal_channel_counters(now);
            }
        });
}

std::wstring module_path() {
    std::vector<wchar_t> buf(MAX_PATH);
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) return {};
        if (n < buf.size()) return std::wstring(buf.data(), n);
        if (buf.size() >= 32768) return {};
        buf.resize(buf.size() * 2);
    }
}

std::wstring data_dir(const std::wstring& exe) {
    return exe.substr(0, exe.find_last_of(L"\\/")) + L"\\reframework\\data\\re2net\\native-door";
}

// SHA-256 of the running executable's file (read-only, shared). Empty on any failure.
std::string file_sha256(const std::wstring& path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return {};
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    std::string hex;
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) &&
        BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0))) {
        std::vector<unsigned char> buf(1 << 20);
        bool ok = true;
        for (;;) {
            DWORD n = 0;
            if (!ReadFile(f, buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr)) { ok = false; break; }
            if (n == 0) break;
            if (!BCRYPT_SUCCESS(BCryptHashData(h, buf.data(), n, 0))) { ok = false; break; }
        }
        unsigned char digest[32]{};
        if (ok && BCRYPT_SUCCESS(BCryptFinishHash(h, digest, sizeof(digest), 0))) {
            static const char* hexd = "0123456789abcdef";
            for (unsigned char b : digest) { hex.push_back(hexd[b >> 4]); hex.push_back(hexd[b & 15]); }
        }
    }
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(f);
    return hex;
}

}  // namespace

extern "C" __declspec(dllexport) void reframework_plugin_required_version(REFrameworkPluginVersion* v) {
    v->major = REFRAMEWORK_PLUGIN_VERSION_MAJOR;
    v->minor = REFRAMEWORK_PLUGIN_VERSION_MINOR;
    v->patch = REFRAMEWORK_PLUGIN_VERSION_PATCH;
    v->game_name = nullptr;   // the runtime game name is checked exactly in initialize
}

extern "C" __declspec(dllexport) bool reframework_plugin_initialize(const REFrameworkPluginInitializeParam* p) {
    Plugin* plugin = nullptr;
    try {
        if (!p || !p->version || !p->functions || !p->sdk) return false;
        auto log_error = p->functions->log_error;
        if (p->version->major != REFRAMEWORK_PLUGIN_VERSION_MAJOR || p->version->minor < REFRAMEWORK_PLUGIN_VERSION_MINOR)
            return false;
        if (!p->version->game_name || std::string(p->version->game_name) != "RE2") {
            if (log_error) log_error("[re2net_door] unsupported game; not registering");
            return false;
        }
        if (!p->functions->on_post_application_entry || !p->sdk->functions || !p->sdk->functions->add_hook) return false;

        // Exact executable gate (adapter review 1328 finding 5): fail closed before any
        // capability can be offered.
        std::wstring exe = module_path();
        std::string digest = exe.empty() ? std::string() : file_sha256(exe);
        if (digest != kReviewedExeSha256) {
            if (log_error) log_error("[re2net_door] executable is not the reviewed build (%s); not registering",
                                     digest.empty() ? "unreadable" : digest.substr(0, 16).c_str());
            return false;
        }

        // Everything that can throw, before the worker exists.
        auto owned = std::make_unique<Plugin>();
        std::string why;
        if (!owned->bridge.preflight(p->sdk, why)) {
            if (log_error) log_error("[re2net_door] preflight failed: %s", why.c_str());
            return false;   // nothing started, nothing registered
        }
        owned->bridge.set_build_gate(true);
        core::DoorConfig cfg;
        cfg.inbox_cap = 2 * adapter::LocalChannel::kInCap;   // one callback's channel frames always fit
        owned->core = std::make_unique<core::DoorCore>(owned->bridge, owned->transport, owned->journal, cfg);
        // Engine-boundary fence: the local connection the pump adopted must still be the
        // live, unpoisoned one immediately before any engine write (R1328 review).
        owned->core->set_local_fence([pl = owned.get()] { return pl->pump.live(pl->channel); });
        // The retained eligibility hook's authority between pump callbacks (R1446 static
        // review finding 3): plugin not blocked AND the core's current operation still holds
        // exactly this lease with its full pure-state permission, which includes the live
        // local connection (the worker's disconnect/new epoch is visible through channel
        // atomics before the next LateUpdate reset). Engine thread only (the hook checks
        // owner identity first).
        owned->bridge.set_hook_permit([pl = owned.get()](core::ObjRef door, core::ObjRef actor) {
            return adapter::retained_hook_permit(pl->blocked, pl->core.get(), door, actor);
        });
        std::wstring dir = data_dir(exe);
        std::wstring pid = std::to_wstring(GetCurrentProcessId());
        std::wstring pipe = L"\\\\.\\pipe\\re2net-door-v1-" + pid;
        std::wstring journal = dir + L"\\journal-" + pid + L"-" + std::to_wstring(GetTickCount64()) + L".jsonl";
        CreateDirectoryW(dir.c_str(), nullptr);

        plugin = owned.get();
        if (!plugin->channel.start(pipe, journal, why)) {   // false or throw: no worker exists
            if (log_error) log_error("[re2net_door] channel failed: %s", why.c_str());
            return false;
        }
        g = owned.release();   // the worker exists: resident from here on, never freed
        g->fns = p->functions;

        // Registration from here on: never return false after this point.
        REFrameworkTDBHandle tdb = p->sdk->functions->get_tdb();
        g->hooked = p->sdk->tdb->find_method(tdb, "app.ropeway.gimmick.action.GimmickDoorBase", "onOpened");
        if (g->hooked) {
            g->hook_id = p->sdk->functions->add_hook(g->hooked, &on_opened_pre, &on_opened_post, false);
            g->bridge.set_witness_installed(g->hook_id != 0);
        }
        // Eligibility hooks: all three or none usable (a partial set stays inert, since no
        // lease can be granted without set_eligibility_hooks(true)).
        const auto& rr = g->bridge.resolved();
        bool elig = rr.door_update_peeked && rr.door_update_count && rr.door_collect && rr.array_set_value;
        if (elig) {
            unsigned a = p->sdk->functions->add_hook(rr.door_update_peeked, &door_scope_pre, &door_scope_post, false);
            unsigned b = p->sdk->functions->add_hook(rr.door_update_count, &door_scope_pre, &door_scope_post, false);
            unsigned c = p->sdk->functions->add_hook(rr.door_collect, &candidates_pre, &candidates_post, false);
            elig = a != 0 && b != 0 && c != 0;
        }
        g->bridge.set_eligibility_hooks(elig);
        if (!p->functions->on_post_application_entry("LateUpdateBehavior", &on_late_update)) {
            g->blocked = true;
            if (log_error) log_error("[re2net_door] callback registration refused; blocked");
        } else if (p->functions->log_info) {
            p->functions->log_info("[re2net_door] ready (witness %s)", g->hook_id ? "on" : "off");
        }
        return true;
    } catch (...) {
        // g is set exactly when a worker exists: then stay loaded and blocked. Otherwise
        // nothing asynchronous was started and returning false (unload) is safe.
        if (g) { g->blocked = true; return true; }
        return false;
    }
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }   // intentionally empty
