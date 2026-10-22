// DoorCore: the single owner of the ordinary-door interaction transaction on one peer.
//
// Selection: per fence the host proposes kDoorImpl (door_select) and the guest
//        acknowledges (door_select_ack). No native write happens on either peer
//        before that exact fence is selected on both.
// Host:  partner intent -> admission (fence/consent/playing/selection/unique door/
//        actor/host 8 m guard/unlocked/not already open) -> ONE actor-explicit native
//        open -> post-update observation -> door_apply + bounded raw progress ->
//        guest result -> final phase.
// Guest: door_apply -> scene wait -> admission -> ONE mirror open -> optional leaf
//        follow -> local observation -> door_result.
//
// Invariants: engine calls only from tick(); scope (connection/barrier/boots, role,
// consent, selection, actor/door incarnation) re-checked immediately before every
// engine write AND after every external callback before its facts are used or a
// final claim is made; at most one engine-entering open per operation; never a
// second backend or legacy fallback after a write started; facts are tri-state and
// never promoted; every operation ends in exactly one final phase; every outbound
// message is contract-validated before it reaches the transport.
//
// Authority (V2 review 1319): ordered processing of queued messages must not hide a
// known revocation. receive() therefore applies authority DOWNGRADES immediately:
// a disconnect, role change, scope change, consent loss, negative selection or
// matching cancel marks the active operation revoked at once (sticky; a later
// re-grant cannot un-revoke it), and any queued session that would suspend writes
// (not playing, scene change) holds writes until it has been processed. Grants stay
// ordered. permit_revision() counts these immediate revisions.
//
// Legacy reservation (contract review 1245 item 11): the host reserves (blocks its
// legacy door path) BEFORE its first door_select for a scope; the guest BEFORE its
// positive door_select_ack. A send failure or timeout never releases it. Only a
// processed negative ack (host; the guest never reserved) or a scope change that both
// peers observe (connection pair, barrier, boots, role) releases it.
//
// Exceptions: a C++ exception thrown from any callback during tick() is contained.
// The tick guard is restored (RAII), the active operation ends honestly
// (Blocked/native_exception before a write was attempted, Uncertain/native_exception
// after), its messages are deferred to the next tick, and the core latches faulted:
// no further engine writes for its lifetime (no retry).
#pragma once
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <vector>
#include "re2net/core/engine_bridge.hpp"
#include "re2net/core/messages.hpp"
#include "re2net/core/transport.hpp"

namespace re2net::core {

struct DoorConfig {
    float host_near_m = 8.0f;              // existing host guard, unchanged
    uint64_t observe_ms = 6000;            // local observation window after the write
    uint64_t guest_result_ms = 9000;       // host waits this long for door_result
    uint64_t scene_wait_ms = 10000;        // guest waits for the host's scene
    uint64_t select_retry_ms = 1000;       // host re-proposes selection if unacknowledged
    uint64_t progress_interval_ms = 100;   // <= 10 Hz host progress samples
    uint32_t max_progress_samples = 40;
    float progress_threshold = 0.05f;      // change in raw value that counts as progress
    size_t inbox_cap = 32;
    size_t early_cap = 48;                 // guest buffer for messages ahead of door_apply
};

struct DoorFacts {
    Tri admitted = Tri::Unknown;
    Tri engine_entered = Tri::Unknown;   // a native mutation was entered
    Tri native_true = Tri::Unknown;      // the mutation returned true
    Tri on_opened = Tri::Unknown;        // door onOpened ran inside the call
    Tri actor_displaced = Tri::Unknown;  // acting actor moved inside the call
    Tri opened = Tri::Unknown;           // IsOpened (nullable opened side) read true after the write
    Tri progress = Tri::Unknown;         // raw swing value changed by >= threshold after the write
    Tri motion_layer = Tri::Unknown;
    Tri crossed = Tri::Unknown;          // host: partner actor changed door side (host replica)
    Tri follow_applied = Tri::Unknown;   // guest: leaf-follow accepted at least once
    // The partner was a member of this door's own collected candidate list during the
    // engine's update (injected or already present). False: the lease ran but every
    // list was refused (no empty NPC slot). Unknown: no lease, or no scope observed.
    Tri partner_eligible = Tri::Unknown;
    Side opened_side = Side::Unknown;
    uint32_t readable_samples = 0;       // post-write samples with a readable value
    float max_delta = 0.0f;              // largest |value - baseline| seen after the write
};

struct OpView {
    Fence fence;
    uint64_t op = 0;
    uint64_t req = 0;
    Role role = Role::None;
    DoorPhase phase = DoorPhase::None;
    Reason reason = Reason::None;
    bool final = false;
    DoorFacts facts;
    std::optional<ResultMsg> guest_result;  // host only
};

struct CoreCounters {
    uint64_t invocations = 0;        // engine-entering opens (open_by_actor/open_mirror)
    uint64_t follows = 0;
    uint64_t nested_ticks = 0;
    uint64_t inbox_overflow = 0;
    uint64_t send_failures = 0;
    uint64_t invalid_outbound = 0;
    uint64_t duplicates = 0;
    uint64_t out_of_order = 0;
    uint64_t bad_messages = 0;
    uint64_t foreign_fence = 0;      // peer frames whose full fence matched no current op
    uint64_t post_final_mutations = 0;  // must stay 0
    uint64_t writes_refused_scope = 0;  // pre-write scope check refused an engine write
    uint64_t callback_exceptions = 0;   // C++ exceptions contained by tick()
    uint64_t unsolicited_acks = 0;      // door_select_ack without our own door_select in that scope
    uint64_t revalidation_retired = 0;  // ops retired by a post-callback revalidation
    uint64_t local_resets = 0;          // local channel connection changes / losses
    uint64_t baseline_resets = 0;       // value-side identity changed: baseline re-acquired
    uint64_t leases = 0;                // eligibility leases granted (grants and re-grants)
    uint64_t lease_releases = 0;
    uint64_t leases_lost_in_hook = 0;   // the adapter's hook ended a lease the core still counted (R1446)
    uint64_t leases_retired = 0;        // leases given up for the rest of their operation (fault/bound/abandon)
};

class DoorCore {
public:
    DoorCore(EngineBridge& bridge, Transport& transport, Journal& journal, DoorConfig cfg = {});

    // Queue a decoded message. Never touches the engine; safe to call from inside an
    // EngineBridge/Transport/Journal callback. Ordinary processing happens on the next
    // tick, but an authority downgrade is visible to the core immediately (see top).
    void receive(const Message& m);
    // Queue raw text from the local channel. Undecodable text is journaled and treated as
    // a local-channel loss (local_reset); returns false so the caller can drop the client.
    bool receive_text(std::string_view text);
    // The local channel changed connection (or lost a frame): every queued local frame
    // and all local authority (connected/consent/playing, selection) end now; the active
    // operation is revoked (disconnected). Fence, role and the legacy reservation are kept:
    // the peer scope has not changed. A fresh session is required before anything acts.
    void local_reset(const char* why);
    // True once after the core's own inbox had to drop a local frame.
    bool take_local_loss() { bool l = local_loss_; local_loss_ = false; return l; }
    // Optional engine-boundary fence for the local connection (R1328 review): evaluated
    // immediately before every engine write and in every post-callback revalidation; false
    // retires the active operation as disconnected. It must not call into the core.
    void set_local_fence(std::function<bool()> live) { local_fence_ = std::move(live); }
    // Advance on an engine callback (game thread). Re-entrant calls are refused.
    // C++ exceptions from callbacks are contained (see top); tick() does not throw them.
    void tick(uint64_t now_ms);

    std::optional<OpView> active() const;
    const std::vector<OpView>& finished() const { return finished_; }
    const CoreCounters& counters() const { return counters_; }
    const SessionMsg& session() const { return session_; }
    bool selected() const { return selected_ && selected_fence_.same_scope_except_scene(session_.fence); }
    // True while this peer must keep its legacy door path blocked for the current scope.
    bool legacy_reserved() const { return reserved_ && reserved_fence_.same_scope_except_scene(session_.fence); }
    uint64_t permit_revision() const { return permit_rev_; }
    bool faulted() const { return faulted_; }
    // The retained eligibility hook's authority (R1446 static review): true only while the
    // CURRENT operation still holds exactly this (door, actor) lease and every pure-state
    // part of its write permission holds (permit_now: revocation, cancel, overflow, fault,
    // local connection/epoch, session/consent/playing, fence, selection, queued holds).
    // Pure state: no engine/bridge call, journal or message. Engine thread only.
    bool lease_permit(ObjRef door, ObjRef actor) const;
    // The embedder's callback boundary failed and it will stop ticking (R1446): end this
    // operation's lease now, state-only, and never re-grant it. Call on the engine thread.
    void abandon_lease() noexcept;
    CapsMsg caps() const;

private:
    enum class Stage : uint8_t { Pending, WaitScene, Observing, AwaitGuest };
    struct Op {
        OpView view;
        Stage stage = Stage::Pending;
        DoorKey door;
        ActorRole actor = ActorRole::P2;
        Side side_hint = Side::Unknown;   // guest: host's opened side
        ObjRef door_ref{}, actor_ref{};
        Side start_side = Side::Unknown;
        uint64_t created_ms = 0, started_ms = 0, deadline_ms = 0, last_progress_ms = 0;
        uint32_t progress_n = 0;
        std::optional<float> baseline;    // admission value (not itself evidence of progress)
        Side baseline_side = Side::Unknown;   // which PeekedWork side the baseline was measured on
        bool apply_sent = false;
        bool host_done = false;           // host: sent; guest: received
        std::optional<float> follow_target;
        bool cancelled = false;
        bool overflow = false;
        bool invalid_outbound = false;
        Reason revoked = Reason::None;    // immediate, sticky authority downgrade
        bool lease_wanted = false;        // eligibility lease belongs to this op (after a successful open)
        bool lease_held = false;
        uint32_t lease_regrants = 0;      // re-grants after a hook-side loss (bounded)
        uint32_t lease_faults_seen = 0;   // bridge hook_faults at the last grant
        // guest: the host's door_host_done for THIS op/fence, retained (R1328 core-claims review)
        Tri host_progress = Tri::Unknown;
        Tri host_crossed = Tri::Unknown;
        Reason host_reason = Reason::None;
        bool write_attempted = false;     // an engine write (open/follow) was called
        bool status_sent = false, result_recorded = false, result_sent = false;   // finish() progress
    };

    void run_tick(uint64_t now);
    void contain_exception(const char* what);
    void note_revocation(const Message& m);
    std::optional<Reason> queued_hold(const Fence& f, Role role, bool exact_scene) const;
    void process(const Message& m, uint64_t now);
    void on_session(const SessionMsg& m, uint64_t now);
    void on_intent(const IntentMsg& m, uint64_t now);
    void on_cancel(const CancelMsg& m, uint64_t now);
    void on_select(const SelectMsg& m, uint64_t now);
    void on_select_ack(const SelectAckMsg& m, uint64_t now);
    void on_apply(const ApplyMsg& m, uint64_t now);
    void on_progress(const ProgressMsg& m, uint64_t now);
    void on_host_done(const HostDoneMsg& m, uint64_t now);
    void on_result(const ResultMsg& m, uint64_t now);
    bool op_matches(const Fence& f, uint64_t op, Role need) const;

    void maybe_propose(uint64_t now);
    void advance_host(uint64_t now);
    void advance_guest(uint64_t now);
    bool host_admit(uint64_t now);
    bool guest_admit(uint64_t now);
    std::optional<Reason> observe(uint64_t now, bool host);
    std::optional<Reason> scope_lost(bool host);
    std::optional<Reason> write_hold(bool host);
    std::optional<Reason> write_blocked(bool host);
    bool permit_now(bool host) const;   // pure-state permit for the adapter's mutation boundary
    void apply_invoke(const InvokeResult& r, uint64_t now);
    void acquire_open_baseline(uint64_t now, bool host);
    void drop_lease() noexcept;                          // state-only; every retirement path
    void maintain_lease(uint64_t now, bool host, bool hold);
    void reconcile_lease(uint64_t now);                  // pure: hook-side loss -> not held (R1446)
    void fold_eligibility();
    void retire(Reason r, uint64_t now, const char* event);
    void reserve(const Fence& f, uint64_t now, const char* why);
    void release(uint64_t now, const char* why);

    void set_phase(DoorPhase p, Reason r, uint64_t now, const char* event);
    void finish(DoorPhase p, Reason r, uint64_t now, const char* event);
    void refuse_status(const Fence& f, uint64_t req, Reason r, uint64_t now);
    bool send(const Message& m);
    void log(uint64_t now, const char* event, const std::string& detail = {});

    EngineBridge& bridge_;
    Transport& transport_;
    Journal& journal_;
    DoorConfig cfg_;

    SessionMsg session_{};
    std::deque<Message> inbox_;
    std::optional<Op> op_;
    std::vector<OpView> finished_;
    std::vector<std::pair<uint64_t, Message>> early_;      // guest: (op, msg) ahead of apply
    std::vector<std::pair<uint64_t, ResultMsg>> results_;  // guest: final results by op (dedupe)
    CoreCounters counters_{};
    Fence scope_fence_{};          // connection/barrier/boots the counters below belong to
    uint64_t next_op_ = 1;         // host
    uint64_t last_req_ = 0;        // host, per scope
    uint64_t last_op_ = 0;         // guest: highest op accepted, per scope
    bool selected_ = false;
    Fence selected_fence_{};
    uint64_t select_sent_ms_ = 0;
    bool select_pending_ = false;
    bool select_refused_ = false;  // host: peer refused this scope; no re-proposal until it changes
    bool reserved_ = false;        // legacy path reserved (blocked) for reserved_fence_'s scope
    Fence reserved_fence_{};
    uint64_t permit_rev_ = 0;
    bool faulted_ = false;         // a callback threw: no further engine writes
    std::string fault_detail_;
    bool fault_unlogged_ = false;
    std::vector<Message> deferred_;  // messages owed by an operation ended inside the exception handler
    bool in_tick_ = false;
    uint64_t last_now_ = 0;
    bool pending_overflow_ = false;
    bool local_loss_ = false;
    std::function<bool()> local_fence_;
};

}  // namespace re2net::core
