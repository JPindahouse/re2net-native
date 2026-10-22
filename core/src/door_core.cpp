#include "re2net/core/door_core.hpp"

#include <algorithm>
#include <cmath>
#include <exception>

namespace re2net::core {
namespace {
template <class... F> struct Overload : F... { using F::operator()...; };
template <class... F> Overload(F...) -> Overload<F...>;

// Restores the re-entrancy flag on every exit from tick(), including unwinding.
struct TickGuard {
    bool& flag;
    explicit TickGuard(bool& f) : flag(f) { flag = true; }
    ~TickGuard() { flag = false; }
    TickGuard(const TickGuard&) = delete;
    TickGuard& operator=(const TickGuard&) = delete;
};

// A refusal before any write names the missing permission, not its loss.
Reason blocked_reason(Reason r) { return r == Reason::ConsentLost ? Reason::NoConsent : r; }

// Re-grants allowed after the adapter's hook ended a lease without a fault (R1446). Each
// one is a full revalidating lease_eligibility; past the bound the lease is retired.
constexpr uint32_t kMaxLeaseRegrants = 2;
}  // namespace

std::string journal_line(const JournalRecord& r) {
    auto clean = [](std::string s, size_t n) {
        s = s.substr(0, n);
        for (char& c : s) if (c == '"' || c == '\\' || static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7e) c = '_';
        return s;
    };
    return "{\"ms\":" + std::to_string(r.ms) + ",\"conn\":\"" + clean(r.connection, kMaxToken) +
           "\",\"op\":" + std::to_string(r.op) + ",\"req\":" + std::to_string(r.req) +
           ",\"role\":\"" + to_string(r.role) + "\",\"event\":\"" + clean(r.event, 40) +
           "\",\"phase\":\"" + to_string(r.phase) + "\",\"reason\":\"" + to_string(r.reason) +
           "\",\"detail\":\"" + clean(r.detail, 120) + "\"}";
}

DoorCore::DoorCore(EngineBridge& bridge, Transport& transport, Journal& journal, DoorConfig cfg)
    : bridge_(bridge), transport_(transport), journal_(journal), cfg_(cfg) {}

CapsMsg DoorCore::caps() const {
    EngineCaps c = bridge_.caps();
    bool ok = !faulted_ && c.build_ok && c.api_ok && c.door_types_ok && (c.actor_open_ok || c.mirror_open_ok);
    return CapsMsg{ok, 1, ok ? kDoorImpl : "none"};
}

void DoorCore::receive(const Message& m) {
    note_revocation(m);   // before the capacity check: a dropped downgrade still counts
    if (inbox_.size() >= cfg_.inbox_cap) {
        ++counters_.inbox_overflow;
        pending_overflow_ = true;   // the dropped message may belong to the active op
        local_loss_ = true;         // and may have been a session/cancel: the embedder must resync
        if (op_ && !op_->view.final && op_->revoked == Reason::None) op_->revoked = Reason::Overflow;
        drop_lease();   // known overflow ends the retained lease now, not at the next tick (R1446)
        return;
    }
    inbox_.push_back(m);
}

bool DoorCore::receive_text(std::string_view text) {
    std::string err;
    auto m = decode(text, &err);
    if (!m) {
        ++counters_.bad_messages;
        log(last_now_, "bad_message", err);
        local_reset("bad_local_frame");   // it may have been a session or cancel
        return false;
    }
    receive(*m);
    return true;
}

void DoorCore::local_reset(const char* why) {
    ++counters_.local_resets;
    size_t dropped = inbox_.size();
    inbox_.clear();          // every queued frame came from the previous local connection
    early_.clear();
    pending_overflow_ = false;
    local_loss_ = false;
    drop_lease();
    if (op_ && !op_->view.final && op_->revoked == Reason::None) op_->revoked = Reason::Disconnected;
    ++permit_rev_;
    session_.connected = false;
    session_.consent = false;
    session_.playing = false;
    selected_ = false;       // re-established by a new handshake under the next fresh session
    select_pending_ = false;
    log(last_now_, "local_reset", std::string(why ? why : "") + " dropped " + std::to_string(dropped));
}

// Immediate, state-only authority downgrade for the active operation. No callback.
void DoorCore::note_revocation(const Message& m) {
    if (!op_ || op_->view.final) return;
    Op& o = *op_;
    Reason r = Reason::None;
    if (auto* s = std::get_if<SessionMsg>(&m)) {
        if (!s->connected) r = Reason::Disconnected;
        else if (s->role != o.view.role) r = Reason::RoleChanged;
        else if (!s->fence.same_scope_except_scene(o.view.fence)) r = Reason::FenceChanged;
        else if (!s->consent) r = Reason::ConsentLost;
        else if (!s->playing || !s->fence.same_scene(o.view.fence)) ++permit_rev_;   // a hold, via queued_hold()
    } else if (auto* a = std::get_if<SelectAckMsg>(&m)) {
        if (!a->ok && o.view.role == Role::Host && a->fence.same_scope_except_scene(o.view.fence)) r = Reason::NotSelected;
    } else if (auto* c = std::get_if<CancelMsg>(&m)) {
        if (c->op == o.view.op && c->fence.same_scope_except_scene(o.view.fence) && !o.cancelled) {
            o.cancelled = true;
            ++permit_rev_;
        }
    }
    if (r != Reason::None) {
        if (o.revoked == Reason::None) o.revoked = r;
        ++permit_rev_;
    }
    // Any revocation, cancel or write hold ends the eligibility lease at once (state-only):
    // the engine's next door update must not see the partner on a revoked permit.
    if (r != Reason::None || o.cancelled) drop_lease();
    else if (auto* s = std::get_if<SessionMsg>(&m); s && (!s->playing || !s->fence.same_scene(o.view.fence))) drop_lease();
}

void DoorCore::drop_lease() noexcept {
    if (op_ && op_->lease_held) {
        op_->lease_held = false;
        ++counters_.lease_releases;
        bridge_.release_eligibility();
    }
}

void DoorCore::abandon_lease() noexcept {
    if (!op_) return;
    Op& o = *op_;
    if (o.lease_wanted) ++counters_.leases_retired;
    o.lease_wanted = false;   // nothing re-grants it for this operation
    drop_lease();
    bridge_.release_eligibility();   // idempotent: also covers a lease the core no longer counted
}

bool DoorCore::lease_permit(ObjRef door, ObjRef actor) const {
    if (!op_ || !op_->lease_wanted || !op_->lease_held) return false;
    if (!(op_->door_ref == door) || !(op_->actor_ref == actor)) return false;
    return permit_now(op_->view.role == Role::Host);
}

// The lease belongs to an op whose native open succeeded. It is held only while no write
// hold applies (pause, queued suspension, overflow, fault) and is re-granted when the
// hold clears. Every grant is an engine boundary: revalidated before facts are used.
// R1446 static review: the adapter's hook can end the lease between ticks (identity,
// permit or fault). reconcile_lease() reads the bridge's actual state instead of trusting
// the core's own flag; only maintain_lease() (inside an observation, followed by a scope
// revalidation) ever re-grants.
void DoorCore::maintain_lease(uint64_t now, bool host, bool hold) {
    Op& o = *op_;
    if (!o.lease_wanted) return;
    if (hold) { drop_lease(); return; }
    reconcile_lease(now);
    if (!o.lease_wanted || o.lease_held || !bridge_.caps().eligibility_ok) return;
    o.lease_held = bridge_.lease_eligibility(o.door_ref, o.actor_ref);
    if (o.lease_held) {
        o.lease_faults_seen = bridge_.eligibility().hook_faults;
        ++counters_.leases;
        log(now, "eligibility_lease", host ? "host" : "guest");
    }
}

// Pure (bridge state read only, no engine call), every tick of an operation past
// admission, so a hook-side loss is never carried as a held lease, in any stage. A hook
// fault retires the lease for this operation; any other loss consumes one of
// kMaxLeaseRegrants re-grant allowances and, past them, retires it.
void DoorCore::reconcile_lease(uint64_t now) {
    Op& o = *op_;
    if (!o.lease_wanted || !o.lease_held) return;
    EligibilityReport r = bridge_.eligibility();
    if (r.active) return;
    fold_eligibility();   // what the lease did before it ended still counts
    o.lease_held = false;
    ++counters_.leases_lost_in_hook;
    const bool fault = r.hook_faults != o.lease_faults_seen;
    log(now, "eligibility_lease_lost", fault ? "hook_fault" : "hook_revoked");
    if (fault || o.lease_regrants >= kMaxLeaseRegrants) {
        o.lease_wanted = false;
        ++counters_.leases_retired;
        log(now, "eligibility_lease_retired", fault ? "hook_fault" : "regrant_bound");
        return;
    }
    ++o.lease_regrants;
}

void DoorCore::fold_eligibility() {
    Op& o = *op_;
    if (!o.lease_wanted) return;
    EligibilityReport r = bridge_.eligibility();
    auto& f = o.view.facts;
    if (r.injected > 0 || r.already_member > 0) f.partner_eligible = Tri::True;
    else if (r.no_free_slot > 0 && f.partner_eligible == Tri::Unknown) f.partner_eligible = Tri::False;
}

// A session still waiting in the inbox that would suspend or end authority for this
// fence/role. Grants are processed in order; known downgrades are not hidden by it.
std::optional<Reason> DoorCore::queued_hold(const Fence& f, Role role, bool exact_scene) const {
    for (auto& m : inbox_) {
        auto* s = std::get_if<SessionMsg>(&m);
        if (!s) continue;
        if (!s->connected) return Reason::Disconnected;
        if (s->role != role) return Reason::RoleChanged;
        if (!s->fence.same_scope_except_scene(f)) return Reason::FenceChanged;
        if (!s->consent) return Reason::NoConsent;
        if (!s->playing) return Reason::NotPlaying;
        if (exact_scene && !s->fence.same_scene(f)) return Reason::SceneMismatch;
    }
    return std::nullopt;
}

void DoorCore::tick(uint64_t now) {
    if (in_tick_) {           // re-entered from inside a bridge/transport/journal callback
        ++counters_.nested_ticks;
        return;
    }
    TickGuard guard(in_tick_);
    try {
        run_tick(now);
    } catch (const std::exception& e) {
        contain_exception(e.what());
    } catch (...) {
        contain_exception("non_standard_exception");
    }
}

void DoorCore::run_tick(uint64_t now) {
    last_now_ = now;
    if (fault_unlogged_) {
        fault_unlogged_ = false;
        log(now, "callback_exception", fault_detail_);
    }
    if (!deferred_.empty()) {
        std::vector<Message> owed;
        owed.swap(deferred_);
        for (auto& m : owed) send(m);
    }
    for (size_t n = inbox_.size(); n > 0 && !inbox_.empty(); --n) {
        Message m = std::move(inbox_.front());
        inbox_.pop_front();
        process(m, now);
    }
    if (pending_overflow_) {
        pending_overflow_ = false;
        if (op_) op_->overflow = true;
        log(now, "inbox_overflow");
    }
    maybe_propose(now);
    if (op_) {
        if (op_->view.role == Role::Host) advance_host(now);
        else advance_guest(now);
    }
}

// Runs inside the catch handler: state changes only, no callback of any kind. What
// the operation owes its peers is sent on the next tick.
void DoorCore::contain_exception(const char* what) {
    ++counters_.callback_exceptions;
    faulted_ = true;
    fault_detail_ = what ? std::string(what).substr(0, 100) : std::string();
    fault_unlogged_ = true;
    drop_lease();   // noexcept, state-only release
    if (!op_) return;
    Op& o = *op_;
    auto& f = o.view.facts;
    bool wrote = o.write_attempted || f.engine_entered == Tri::True;
    if (!o.view.final) {
        if (f.engine_entered == Tri::True && f.progress == Tri::Unknown && f.readable_samples > 0) f.progress = Tri::False;
        o.view.phase = wrote ? DoorPhase::Uncertain : DoorPhase::Blocked;
        o.view.reason = Reason::NativeException;
        o.view.final = true;
    }
    if (!o.status_sent) deferred_.push_back(StatusMsg{o.view.fence, o.view.op, o.view.req, o.view.role, o.view.phase, o.view.reason});
    if (o.view.role == Role::Guest && !o.result_sent) {
        ResultMsg rm{o.view.fence, o.view.op, o.view.phase, o.view.reason, f.opened, f.progress};
        if (!o.result_recorded) {
            results_.push_back({o.view.op, rm});
            if (results_.size() > 16) results_.erase(results_.begin());
        }
        deferred_.push_back(rm);
    }
    if (o.view.role == Role::Host && o.apply_sent && !o.host_done)
        deferred_.push_back(HostDoneMsg{o.view.fence, o.view.op, f.progress, f.crossed, Reason::NativeException});
    finished_.push_back(o.view);
    op_.reset();
}

std::optional<OpView> DoorCore::active() const {
    if (!op_) return std::nullopt;
    return op_->view;
}

// ------------------------------------------------------------------ inbound
void DoorCore::process(const Message& m, uint64_t now) {
    std::visit(Overload{
        [&](const SessionMsg& x) { on_session(x, now); },
        [&](const IntentMsg& x) { on_intent(x, now); },
        [&](const CancelMsg& x) { on_cancel(x, now); },
        [&](const SelectMsg& x) { on_select(x, now); },
        [&](const SelectAckMsg& x) { on_select_ack(x, now); },
        [&](const ApplyMsg& x) { on_apply(x, now); },
        [&](const ProgressMsg& x) { on_progress(x, now); },
        [&](const HostDoneMsg& x) { on_host_done(x, now); },
        [&](const ResultMsg& x) { on_result(x, now); },
        [&](const StatusMsg&) { ++counters_.bad_messages; log(now, "unexpected_status"); },
        [&](const CapsMsg&) { ++counters_.bad_messages; log(now, "unexpected_caps"); },
    }, m);
}

void DoorCore::on_session(const SessionMsg& m, uint64_t now) {
    bool role_changed = m.role != session_.role;
    bool scope_changed = !m.fence.same_scope_except_scene(scope_fence_) || role_changed;
    session_ = m;
    if (scope_changed) {
        // The old scope's operation ends here, before any fresh-scope request queued
        // behind this session is consumed.
        if (op_) {
            if (op_->revoked == Reason::None) op_->revoked = role_changed ? Reason::RoleChanged : Reason::FenceChanged;
            retire(op_->revoked, now, "scope_replaced");
        }
        if (reserved_) release(now, "scope_changed");
        scope_fence_ = m.fence;
        last_req_ = 0;
        last_op_ = 0;
        results_.clear();
        early_.clear();
        selected_ = false;
        select_pending_ = false;
        select_refused_ = false;
    }
    log(now, "session", std::string(to_string(m.role)) + (m.connected ? " up" : " down") +
                            (m.consent ? " consent" : "") + (m.playing ? " playing" : ""));
}

bool DoorCore::op_matches(const Fence& f, uint64_t op, Role need) const {
    return op_ && op_->view.role == need && op_->view.op == op && op_->view.fence == f;
}

void DoorCore::on_intent(const IntentMsg& m, uint64_t now) {
    if (session_.role != Role::Host) { ++counters_.bad_messages; log(now, "intent_not_host"); return; }
    if (!(m.fence == session_.fence)) {
        ++counters_.foreign_fence;
        refuse_status(session_.fence, m.req, Reason::FenceChanged, now);
        return;
    }
    if (m.req <= last_req_) {
        ++counters_.duplicates;
        log(now, "intent_duplicate", "req " + std::to_string(m.req));
        return;
    }
    // Busy is transient: the request id is NOT consumed, so the same request may be
    // retried once the current operation has ended.
    if (op_) { refuse_status(session_.fence, m.req, Reason::Busy, now); return; }
    last_req_ = m.req;
    Op o;
    o.view.fence = m.fence;
    o.view.op = next_op_++;
    o.view.req = m.req;
    o.view.role = Role::Host;
    o.stage = Stage::Pending;
    o.door = m.door;
    o.actor = m.actor;
    o.created_ms = now;
    op_ = std::move(o);
    log(now, "intent", m.door.name);
}

void DoorCore::on_cancel(const CancelMsg& m, uint64_t now) {
    if (op_ && op_->view.op == m.op && op_->view.fence.same_scope_except_scene(m.fence)) {
        op_->cancelled = true;
        log(now, "cancel");
    }
}

void DoorCore::reserve(const Fence& f, uint64_t now, const char* why) {
    if (reserved_ && reserved_fence_.same_scope_except_scene(f)) return;
    reserved_ = true;
    reserved_fence_ = f;
    log(now, "legacy_reserved", why);
}

void DoorCore::release(uint64_t now, const char* why) {
    reserved_ = false;
    log(now, "legacy_released", why);
}

void DoorCore::maybe_propose(uint64_t now) {
    if (session_.role != Role::Host || !session_.connected || !session_.consent || !session_.fence.valid()) return;
    if (selected() || select_refused_ || faulted_) return;
    EngineCaps c = bridge_.caps();
    if (!(c.build_ok && c.api_ok && c.door_types_ok && c.actor_open_ok)) return;
    if (queued_hold(session_.fence, Role::Host, false)) return;   // a known downgrade is waiting
    if (select_pending_ && now - select_sent_ms_ < cfg_.select_retry_ms) return;
    // Reserve BEFORE the proposal can reach the peer; a failed or unanswered send never
    // releases it (the frame may have been delivered).
    reserve(session_.fence, now, "before_select");
    select_pending_ = true;
    select_sent_ms_ = now;
    if (send(SelectMsg{session_.fence, kDoorImpl})) log(now, "select_sent");
}

void DoorCore::on_select(const SelectMsg& m, uint64_t now) {
    if (session_.role != Role::Guest) { ++counters_.bad_messages; log(now, "select_not_guest"); return; }
    EngineCaps c = bridge_.caps();
    Reason why = Reason::None;
    if (!session_.connected || !session_.fence.valid() || !m.fence.same_scope_except_scene(session_.fence)) why = Reason::FenceChanged;
    else if (m.impl != kDoorImpl) why = Reason::Unsupported;
    else if (faulted_ || !(c.build_ok && c.api_ok && c.door_types_ok && c.mirror_open_ok)) why = Reason::Unsupported;
    else if (auto h = queued_hold(m.fence, Role::Guest, false); h && *h != Reason::NotPlaying && *h != Reason::NoConsent)
        why = Reason::FenceChanged;   // a queued disconnect/role/scope change is already known
    bool ok = why == Reason::None;
    if (ok) reserve(m.fence, now, "before_ack");   // before the ack can reach the host
    // Echo the proposal's fence so the host can match it exactly.
    send(SelectAckMsg{m.fence, kDoorImpl, ok, why});
    if (ok) { selected_ = true; selected_fence_ = m.fence; }
    log(now, ok ? "select_acked" : "select_refused", to_string(why));
}

void DoorCore::on_select_ack(const SelectAckMsg& m, uint64_t now) {
    if (session_.role != Role::Host || !m.fence.same_scope_except_scene(session_.fence) || m.impl != kDoorImpl) {
        ++counters_.foreign_fence;
        log(now, "select_ack_foreign");
        return;
    }
    // Only an answer to our own proposal in this scope counts: the host reserved its
    // legacy path before proposing, so an unsolicited ack cannot enable native writes.
    if (!legacy_reserved() || select_refused_) {
        ++counters_.unsolicited_acks;
        log(now, "select_ack_unsolicited");
        return;
    }
    select_pending_ = false;
    selected_ = m.ok;
    selected_fence_ = m.fence;
    if (!m.ok) {
        select_refused_ = true;
        release(now, "peer_refused");   // mutual agreement: the guest stays legacy too
    }
    log(now, m.ok ? "selected" : "selection_refused", to_string(m.reason));
}

void DoorCore::on_apply(const ApplyMsg& m, uint64_t now) {
    if (session_.role != Role::Guest) { ++counters_.bad_messages; log(now, "apply_not_guest"); return; }
    if (!m.fence.same_scope_except_scene(session_.fence)) { ++counters_.foreign_fence; log(now, "apply_foreign"); return; }
    if (m.op < last_op_) { ++counters_.out_of_order; log(now, "apply_old", std::to_string(m.op)); return; }
    if (m.op == last_op_) {
        ++counters_.duplicates;
        for (auto& [op, r] : results_) {
            if (op == m.op && r.fence == m.fence) {   // repeated delivery returns the same outcome
                send(r);
                log(now, "apply_duplicate_resend", std::to_string(m.op));
                return;
            }
        }
        log(now, "apply_duplicate", std::to_string(m.op));
        return;
    }
    if (op_) finish(DoorPhase::Interrupted, Reason::Stale, now, "superseded");
    last_op_ = m.op;
    Op o;
    o.view.fence = m.fence;
    o.view.op = m.op;
    o.view.req = m.req;
    o.view.role = Role::Guest;
    o.stage = Stage::WaitScene;
    o.door = m.door;
    o.side_hint = m.side;
    o.created_ms = now;
    o.deadline_ms = now + cfg_.scene_wait_ms;
    op_ = std::move(o);
    log(now, "apply", m.door.name + " side " + to_string(m.side));
    // Frames that overtook door_apply for this exact op and fence are honored now.
    std::vector<std::pair<uint64_t, Message>> keep;
    std::vector<Message> mine;
    for (auto& [op, msg] : early_) {
        if (op == m.op) mine.push_back(msg);
        else if (op > m.op) keep.push_back({op, msg});
    }
    early_.swap(keep);
    for (auto& msg : mine) process(msg, now);
}

void DoorCore::on_progress(const ProgressMsg& m, uint64_t now) {
    if (session_.role != Role::Guest) { ++counters_.bad_messages; return; }
    if (op_matches(m.fence, m.op, Role::Guest)) {
        if (m.n <= op_->progress_n) { ++counters_.duplicates; return; }
        op_->progress_n = m.n;
        op_->follow_target = m.value.to_float();
        return;
    }
    if (m.fence.same_scope_except_scene(session_.fence) && m.op > last_op_) {
        if (early_.size() >= cfg_.early_cap) { pending_overflow_ = true; ++counters_.inbox_overflow; return; }
        early_.push_back({m.op, m});
        return;
    }
    ++counters_.foreign_fence;
    log(now, "progress_foreign", std::to_string(m.op));
}

void DoorCore::on_host_done(const HostDoneMsg& m, uint64_t now) {
    if (session_.role != Role::Guest) { ++counters_.bad_messages; return; }
    if (op_matches(m.fence, m.op, Role::Guest)) {
        if (op_->host_done) { ++counters_.duplicates; return; }   // the first outcome for this op stands
        op_->host_done = true;
        op_->host_progress = m.progress;
        op_->host_crossed = m.crossed;
        op_->host_reason = m.reason;
        log(now, "host_done", std::string("progress ") + to_string(m.progress) + " reason " + to_string(m.reason));
        return;
    }
    if (m.fence.same_scope_except_scene(session_.fence) && m.op > last_op_) {
        if (early_.size() >= cfg_.early_cap) { pending_overflow_ = true; ++counters_.inbox_overflow; return; }
        early_.push_back({m.op, m});
        return;
    }
    ++counters_.foreign_fence;
}

void DoorCore::on_result(const ResultMsg& m, uint64_t now) {
    if (session_.role != Role::Host) { ++counters_.bad_messages; return; }
    if (op_matches(m.fence, m.op, Role::Host) && (op_->stage == Stage::Observing || op_->stage == Stage::AwaitGuest)) {
        if (op_->view.guest_result) { ++counters_.duplicates; return; }
        op_->view.guest_result = m;
        log(now, "guest_result", std::string(to_string(m.phase)) + " progress " + to_string(m.progress));
        return;
    }
    for (auto& f : finished_) if (f.op == m.op && f.fence == m.fence) { ++counters_.duplicates; return; }
    ++counters_.foreign_fence;
    log(now, "result_foreign", std::to_string(m.op));
}

// ------------------------------------------------------------------ scope
// Engine queries run first: a revocation queued from inside them is then seen by the
// state checks below in the same evaluation.
std::optional<Reason> DoorCore::scope_lost(bool host) {
    Op& o = *op_;
    bool door_ok = !o.door_ref.valid() || bridge_.still_valid(o.door_ref);
    bool actor_ok = !o.actor_ref.valid() || bridge_.still_valid(o.actor_ref);
    if (o.revoked != Reason::None) return o.revoked;
    if (local_fence_ && !local_fence_()) return Reason::Disconnected;   // the local connection is no longer live
    if (o.cancelled) return Reason::Cancelled;
    if (!session_.connected) return Reason::Disconnected;
    if (session_.role != o.view.role) return Reason::RoleChanged;
    if (host ?!(session_.fence == o.view.fence)
             : !(session_.fence.same_scope_except_scene(o.view.fence) && session_.fence.same_scene(o.view.fence)))
        return Reason::FenceChanged;
    if (!session_.consent) return Reason::ConsentLost;
    if (!(selected_ && selected_fence_.same_scope_except_scene(o.view.fence))) return Reason::NotSelected;
    if (!door_ok || !actor_ok) return Reason::Stale;
    return std::nullopt;
}

// Conditions that suspend an engine write without retiring the operation by
// themselves: paused/loading, a queued suspending session, pending overflow, fault.
std::optional<Reason> DoorCore::write_hold(bool host) {
    if (local_fence_ && !local_fence_()) return Reason::Disconnected;
    if (!session_.playing) return Reason::NotPlaying;
    if (auto r = queued_hold(op_->view.fence, op_->view.role, true)) return r;
    if (pending_overflow_) return Reason::Overflow;
    if (faulted_) return Reason::Unsupported;
    if (op_->view.final) { ++counters_.post_final_mutations; return Reason::Stale; }
    (void)host;
    return std::nullopt;
}

// Immediately before any engine write: full scope plus every hold.
std::optional<Reason> DoorCore::write_blocked(bool host) {
    if (auto r = scope_lost(host)) return r;
    return write_hold(host);
}

// The authority the adapter re-checks AFTER its own final engine reads, immediately
// before the mutating invoke (R1414 static review finding 1). Pure state only: no
// engine or bridge call, no journal, no message; the adapter calls it exactly once.
// Object identity is the adapter's own re-resolution just before; this adds every
// state-only part of write_blocked (revocation, fence, session, selection, holds).
bool DoorCore::permit_now(bool host) const {
    if (!op_ || op_->view.final) return false;
    const Op& o = *op_;
    if (o.revoked != Reason::None || o.cancelled || o.overflow || o.invalid_outbound) return false;
    if (faulted_ || pending_overflow_) return false;
    if (local_fence_ && !local_fence_()) return false;
    if (!session_.connected || !session_.consent || !session_.playing || session_.role != o.view.role) return false;
    const bool fence_ok = host ? session_.fence == o.view.fence
                               : session_.fence.same_scope_except_scene(o.view.fence) && session_.fence.same_scene(o.view.fence);
    if (!fence_ok) return false;
    if (!(selected_ && selected_fence_.same_scope_except_scene(o.view.fence))) return false;
    if (queued_hold(o.view.fence, o.view.role, true)) return false;
    return true;
}

// Ends the operation after a scope loss: Blocked if no engine write was attempted,
// Interrupted otherwise. The host tells the guest if door_apply already went out.
void DoorCore::retire(Reason r, uint64_t now, const char* event) {
    Op& o = *op_;
    bool wrote = o.write_attempted || o.view.facts.engine_entered == Tri::True;
    if (o.view.role == Role::Host && o.apply_sent && !o.host_done) {
        o.host_done = true;
        send(HostDoneMsg{o.view.fence, o.view.op, o.view.facts.progress, o.view.facts.crossed, r});
    }
    finish(wrote ? DoorPhase::Interrupted : DoorPhase::Blocked, wrote ? r : blocked_reason(r), now, event);
}

// ------------------------------------------------------------------ host
void DoorCore::advance_host(uint64_t now) {
    Op& o = *op_;
    if (o.stage == Stage::Pending) { host_admit(now); return; }

    reconcile_lease(now);   // pure: also covers AwaitGuest, where nothing re-grants
    auto lost = scope_lost(true);
    // Passing through can change the host's room: a crossed partner is a host-local
    // completion, not an interruption, provided only the scene changed.
    if (lost == Reason::FenceChanged && o.revoked == Reason::None && o.view.facts.crossed == Tri::True &&
        session_.connected && session_.fence.same_scope_except_scene(o.view.fence)) {
        if (!o.host_done && o.apply_sent) {
            if (!send(HostDoneMsg{o.view.fence, o.view.op, o.view.facts.progress, Tri::True, Reason::None})) return;
            o.host_done = true;
            o.stage = Stage::AwaitGuest;
            o.deadline_ms = now + cfg_.guest_result_ms;
            log(now, "host_local_done_scene_changed");
        }
        lost.reset();
        if (o.stage != Stage::AwaitGuest) {   // never opened with a side before leaving
            finish(DoorPhase::Uncertain, Reason::NoProgress, now, "host_never_opened");
            return;
        }
    }
    if (lost) { retire(*lost, now, "scope_lost"); return; }
    if (o.cancelled || o.overflow || o.invalid_outbound) {
        retire(o.cancelled ? Reason::Cancelled : o.overflow ? Reason::Overflow : Reason::InvalidOutbound, now, "retired");
        return;
    }
    if (o.stage == Stage::Observing) {
        if (auto r = observe(now, true)) { ++counters_.revalidation_retired; retire(*r, now, "revalidation"); return; }
        if (!op_ || o.overflow || o.invalid_outbound) return;
        if (o.view.facts.crossed == Tri::True || now >= o.deadline_ms) {
            if (!o.apply_sent) {
                finish(DoorPhase::Uncertain, Reason::NoProgress, now, "host_never_opened");
                return;
            }
            auto& f = o.view.facts;
            if (f.progress == Tri::Unknown && f.readable_samples > 0) f.progress = Tri::False;
            if (f.crossed == Tri::Unknown && o.start_side != Side::Unknown) f.crossed = Tri::False;
            if (!send(HostDoneMsg{o.view.fence, o.view.op, f.progress, f.crossed, Reason::None})) return;
            o.host_done = true;
            o.stage = Stage::AwaitGuest;
            o.deadline_ms = now + cfg_.guest_result_ms;
            log(now, "host_local_done");
        }
        return;
    }
    // AwaitGuest. The scope check above was the last external callback before the
    // final claim below.
    if (o.view.guest_result) {
        const ResultMsg& g = *o.view.guest_result;
        Tri hp = o.view.facts.progress, gp = g.progress;
        if (hp == Tri::True && gp == Tri::True)
            finish(o.view.facts.crossed == Tri::True ? DoorPhase::OpenBothPartnerCrossedHost : DoorPhase::OpenBoth,
                   Reason::None, now, "final");
        else if (hp == Tri::True || gp == Tri::True)
            finish(DoorPhase::Mismatch, hp == Tri::True ? (g.reason != Reason::None ? g.reason : Reason::NoProgress)
                                                        : Reason::NoProgress, now, "final");
        else
            finish(DoorPhase::Uncertain, Reason::NoProgress, now, "final");
        return;
    }
    if (now >= o.deadline_ms) finish(DoorPhase::Uncertain, Reason::GuestTimeout, now, "guest_timeout");
}

bool DoorCore::host_admit(uint64_t now) {
    Op& o = *op_;
    auto refuse = [&](Reason r) { finish(DoorPhase::Blocked, blocked_reason(r), now, "refused"); return false; };
    if (o.revoked != Reason::None) return refuse(o.revoked);
    if (!session_.connected) return refuse(Reason::Disconnected);
    if (session_.role != Role::Host) return refuse(Reason::RoleChanged);
    if (!(session_.fence == o.view.fence)) return refuse(Reason::FenceChanged);
    if (!session_.consent) return refuse(Reason::NoConsent);
    if (!session_.playing) return refuse(Reason::NotPlaying);
    if (!selected()) return refuse(Reason::NotSelected);
    if (o.cancelled) return refuse(Reason::Cancelled);
    if (o.overflow) return refuse(Reason::Overflow);
    if (faulted_) return refuse(Reason::Unsupported);
    if (o.actor != ActorRole::P2) return refuse(Reason::Unsupported);
    if (o.door.location != o.view.fence.scene_location || o.door.room != o.view.fence.scene_room) return refuse(Reason::SceneMismatch);
    EngineCaps c = bridge_.caps();
    if (!c.build_ok || !c.api_ok || !c.door_types_ok || !c.actor_open_ok) return refuse(Reason::Unsupported);

    Lookup d = bridge_.resolve_door(o.door);
    switch (d.status) {
        case LookupStatus::Found: break;
        case LookupStatus::Missing: return refuse(Reason::DoorMissing);
        case LookupStatus::Duplicate: return refuse(Reason::DoorDuplicate);
        case LookupStatus::NotLoaded: return refuse(Reason::DoorNotLoaded);
        default: return refuse(Reason::Unsupported);
    }
    Lookup a = bridge_.resolve_actor(ActorRole::P2);
    if (a.status != LookupStatus::Found) return refuse(Reason::ActorMissing);
    Lookup p1 = bridge_.resolve_actor(ActorRole::P1);
    if (p1.status != LookupStatus::Found) return refuse(Reason::DistanceUnknown);
    auto dist = bridge_.distance(p1.ref, d.ref);
    if (!dist || !std::isfinite(*dist)) return refuse(Reason::DistanceUnknown);
    if (*dist > cfg_.host_near_m) return refuse(Reason::HostFar);
    o.door_ref = d.ref;   // bound before the sample so its incarnation is revalidated
    o.actor_ref = a.ref;
    DoorSample s = bridge_.sample(d.ref);
    if (!s.readable) return refuse(Reason::LockUnknown);
    if (s.locked == Tri::True) return refuse(Reason::DoorLocked);
    if (s.locked != Tri::False) return refuse(Reason::LockUnknown);
    if (s.opened == Tri::True) return refuse(Reason::AlreadyOpen);
    if (s.opened != Tri::False) return refuse(Reason::Unsupported);
    o.start_side = bridge_.actor_side(a.ref, d.ref);
    o.baseline = s.value;
    o.baseline_side = s.value_side;

    // Every admission fact above came from a callback: revalidate scope, incarnation
    // and holds after the last of them, immediately before the write.
    if (auto r = write_blocked(true)) { ++counters_.writes_refused_scope; return refuse(*r); }
    o.view.facts.admitted = Tri::True;
    log(now, "admitted", "dist_dm " + std::to_string(static_cast<int>(*dist * 10)) + " side " + to_string(o.start_side));
    if (auto r = write_blocked(true)) { ++counters_.writes_refused_scope; return refuse(*r); }   // the journal is a callback too
    o.write_attempted = true;
    InvokeResult res = bridge_.open_by_actor(o.door_ref, o.actor_ref, [this] { return permit_now(true); });
    if (res.status == InvokeStatus::PermitDenied) {   // refused at the adapter's boundary: not entered
        o.write_attempted = false;
        ++counters_.writes_refused_scope;
        log(now, "invoke_permit_denied", "open_by_actor");
        return refuse(write_blocked(true).value_or(Reason::Stale));
    }
    if (engine_entered(res.status)) ++counters_.invocations;
    log(now, "invoke", "open_by_actor");
    if (!op_) return false;
    apply_invoke(res, now);
    if (op_ && o.stage == Stage::Observing) {
        if (auto r = scope_lost(true)) { ++counters_.revalidation_retired; retire(*r, now, "revalidation"); }
        else acquire_open_baseline(now, true);
    }
    return op_.has_value();
}

// ------------------------------------------------------------------ guest
void DoorCore::advance_guest(uint64_t now) {
    Op& o = *op_;
    if (o.stage == Stage::WaitScene) {
        auto refuse = [&](Reason r) { finish(DoorPhase::Blocked, blocked_reason(r), now, "refused"); };
        if (o.revoked != Reason::None) { refuse(o.revoked); return; }
        if (!session_.connected) { refuse(Reason::Disconnected); return; }
        if (session_.role != Role::Guest) { refuse(Reason::RoleChanged); return; }
        if (!session_.fence.same_scope_except_scene(o.view.fence)) { refuse(Reason::FenceChanged); return; }
        if (!session_.consent) { refuse(Reason::NoConsent); return; }
        if (o.cancelled) { refuse(Reason::Cancelled); return; }
        if (o.overflow) { refuse(Reason::Overflow); return; }
        if (!session_.fence.same_scene(o.view.fence)) {
            if (o.view.phase != DoorPhase::WaitingPartnerScene)
                set_phase(DoorPhase::WaitingPartnerScene, Reason::None, now, "wait_scene");
            if (op_ && now >= o.deadline_ms) refuse(Reason::SceneTimeout);
            return;
        }
        o.stage = Stage::Pending;
    }
    if (o.stage == Stage::Pending) { guest_admit(now); return; }

    // OpenBoth needs BOTH sides affirmatively: local motion here, and the host's own
    // accepted outcome for this op/fence saying its leaf progressed with no failure reason.
    const bool host_affirmative = o.host_done && o.host_progress == Tri::True && o.host_reason == Reason::None;
    if (auto r = scope_lost(false)) {
        bool moved_then_scene = *r == Reason::FenceChanged && o.revoked == Reason::None && host_affirmative &&
                                o.view.facts.progress == Tri::True && session_.connected &&
                                session_.fence.same_scope_except_scene(o.view.fence);
        if (moved_then_scene) finish(DoorPhase::OpenBoth, Reason::None, now, "guest_local_done_scene_changed");
        else retire(*r, now, "scope_lost");
        return;
    }
    if (o.cancelled || o.overflow || o.invalid_outbound) {
        retire(o.cancelled ? Reason::Cancelled : o.overflow ? Reason::Overflow : Reason::InvalidOutbound, now, "retired");
        return;
    }
    if (auto r = observe(now, false)) { ++counters_.revalidation_retired; retire(*r, now, "revalidation"); return; }
    if (!op_) return;
    // observe() revalidated after its last callback; nothing external runs between
    // that check and the final claim.
    const bool moved = o.view.facts.progress == Tri::True;
    if (o.host_done && moved) {
        if (host_affirmative) finish(DoorPhase::OpenBoth, Reason::None, now, "guest_local_done");
        else if (o.host_progress == Tri::False)   // the host says its leaf did not move
            finish(DoorPhase::Mismatch, o.host_reason != Reason::None ? o.host_reason : Reason::NoProgress, now,
                   "host_did_not_progress");
        else                                      // host progress unknown, or a failure reason
            finish(DoorPhase::Uncertain, o.host_reason != Reason::None ? o.host_reason : Reason::NoProgress, now,
                   "host_outcome_not_affirmative");
    } else if (now >= o.deadline_ms) {
        // A timeout never invents success: without the host's outcome, local motion alone
        // is not "both". GuestTimeout here means "the peer's outcome did not arrive".
        if (moved) finish(DoorPhase::Uncertain, Reason::GuestTimeout, now, "host_outcome_missing");
        else finish(DoorPhase::Uncertain, Reason::NoProgress, now, "guest_local_done");
    }
}

bool DoorCore::guest_admit(uint64_t now) {
    Op& o = *op_;
    auto refuse = [&](Reason r) { finish(DoorPhase::Blocked, blocked_reason(r), now, "refused"); return false; };
    if (o.revoked != Reason::None) return refuse(o.revoked);
    if (!session_.connected) return refuse(Reason::Disconnected);
    if (session_.role != Role::Guest) return refuse(Reason::RoleChanged);
    if (!session_.consent) return refuse(Reason::NoConsent);
    if (!session_.playing) return refuse(Reason::NotPlaying);
    if (!(selected_ && selected_fence_.same_scope_except_scene(o.view.fence))) return refuse(Reason::NotSelected);
    if (faulted_) return refuse(Reason::Unsupported);
    if (o.door.location != o.view.fence.scene_location || o.door.room != o.view.fence.scene_room) return refuse(Reason::SceneMismatch);
    if (o.side_hint != Side::A && o.side_hint != Side::B) return refuse(Reason::BadMessage);
    EngineCaps c = bridge_.caps();
    if (!c.build_ok || !c.api_ok || !c.door_types_ok || !c.mirror_open_ok) return refuse(Reason::Unsupported);
    Lookup d = bridge_.resolve_door(o.door);
    switch (d.status) {
        case LookupStatus::Found: break;
        case LookupStatus::Missing: return refuse(Reason::DoorMissing);
        case LookupStatus::Duplicate: return refuse(Reason::DoorDuplicate);
        case LookupStatus::NotLoaded: return refuse(Reason::DoorNotLoaded);
        default: return refuse(Reason::Unsupported);
    }
    Lookup a = bridge_.resolve_actor(o.actor);
    if (a.status != LookupStatus::Found) return refuse(Reason::ActorMissing);
    o.door_ref = d.ref;
    o.actor_ref = a.ref;
    DoorSample s = bridge_.sample(d.ref);
    if (!s.readable) return refuse(Reason::LockUnknown);
    if (s.locked == Tri::True) return refuse(Reason::DoorLocked);
    if (s.locked != Tri::False) return refuse(Reason::LockUnknown);
    if (s.opened == Tri::True) { o.view.facts.opened = Tri::True; return refuse(Reason::AlreadyOpen); }
    if (s.opened != Tri::False) return refuse(Reason::Unsupported);
    o.baseline = s.value;
    o.baseline_side = s.value_side;

    if (auto r = write_blocked(false)) { ++counters_.writes_refused_scope; return refuse(*r); }
    o.view.facts.admitted = Tri::True;
    log(now, "admitted", "side " + std::string(to_string(o.side_hint)));
    if (auto r = write_blocked(false)) { ++counters_.writes_refused_scope; return refuse(*r); }
    o.write_attempted = true;
    InvokeResult res = bridge_.open_mirror(o.door_ref, o.actor_ref, o.side_hint, [this] { return permit_now(false); });
    if (res.status == InvokeStatus::PermitDenied) {   // refused at the adapter's boundary: not entered
        o.write_attempted = false;
        ++counters_.writes_refused_scope;
        log(now, "invoke_permit_denied", "open_mirror");
        return refuse(write_blocked(false).value_or(Reason::Stale));
    }
    if (engine_entered(res.status)) ++counters_.invocations;
    log(now, "invoke", "open_mirror");
    if (!op_) return false;
    apply_invoke(res, now);
    if (op_ && o.stage == Stage::Observing) {
        if (auto r = scope_lost(false)) { ++counters_.revalidation_retired; retire(*r, now, "revalidation"); }
        else acquire_open_baseline(now, false);
    }
    return op_.has_value();
}

// Right after the native open returned: the opened side is known and the leaf is at the
// start of its swing, so this side-tagged read is the comparison baseline. It is not a
// progress sample. Revalidated like every other read; an unreadable or side-less read
// leaves the baseline to be acquired by the first side-tagged observation.
void DoorCore::acquire_open_baseline(uint64_t now, bool host) {
    Op& o = *op_;
    DoorSample s = bridge_.sample(o.door_ref);
    if (auto r = scope_lost(host)) { ++counters_.revalidation_retired; retire(*r, now, "revalidation"); return; }
    if (s.readable && s.value && std::isfinite(*s.value) && (s.value_side == Side::A || s.value_side == Side::B)) {
        o.baseline = *s.value;
        o.baseline_side = s.value_side;
        log(now, "open_baseline", to_string(s.value_side));
    }
    // The open succeeded: from here the engine's own door update must count the partner.
    o.lease_wanted = true;
    maintain_lease(now, host, write_hold(host).has_value());
    if (auto r = scope_lost(host)) { ++counters_.revalidation_retired; retire(*r, now, "revalidation"); }
}

// ------------------------------------------------------------------ shared
void DoorCore::apply_invoke(const InvokeResult& res, uint64_t now) {
    Op& o = *op_;
    auto& f = o.view.facts;
    f.engine_entered = tri(engine_entered(res.status));
    f.on_opened = res.on_opened;
    f.actor_displaced = res.actor_displaced;
    switch (res.status) {
        case InvokeStatus::ReturnedTrue:
            f.native_true = Tri::True;
            if (res.on_opened == Tri::False) {   // true without the open mutation (e.g. no-pair branch)
                finish(DoorPhase::Uncertain, Reason::NoOpenMutation, now, "invoke_true_no_onopened");
                return;
            }
            o.stage = Stage::Observing;
            o.started_ms = now;
            o.deadline_ms = now + cfg_.observe_ms;
            set_phase(DoorPhase::Opening, Reason::None, now, "invoke_true");
            return;
        case InvokeStatus::ReturnedFalse:
            f.native_true = Tri::False;
            finish(DoorPhase::Uncertain, Reason::NativeFalse, now, "invoke_false");
            return;
        case InvokeStatus::Exception:
            finish(DoorPhase::Uncertain, Reason::NativeException, now, "invoke_exception");
            return;
        case InvokeStatus::Stale: finish(DoorPhase::Blocked, Reason::Stale, now, "refused"); return;
        case InvokeStatus::NestedRefused: finish(DoorPhase::Blocked, Reason::NestedCall, now, "refused"); return;
        default: finish(DoorPhase::Blocked, Reason::Unsupported, now, "refused"); return;
    }
}

// One observation step. Returns a scope-loss reason when a revalidation after any
// external callback fails; the caller retires. Facts from a read whose scope or
// object incarnation did not survive the read are never folded in.
std::optional<Reason> DoorCore::observe(uint64_t now, bool host) {
    Op& o = *op_;
    auto& f = o.view.facts;
    if (o.lease_wanted) {
        maintain_lease(now, host, write_hold(host).has_value());
        if (auto r = scope_lost(host)) return r;
        fold_eligibility();
    }
    if (!host && o.follow_target && bridge_.caps().follow_ok) {
        if (auto r = scope_lost(false)) return r;
        if (write_hold(false)) {
            ++counters_.writes_refused_scope;   // e.g. paused: no follow write this tick
        } else {
            o.write_attempted = true;
            FollowStatus fs = bridge_.follow(o.door_ref, *o.follow_target);
            ++counters_.follows;
            if (auto r = scope_lost(false)) return r;
            if (fs == FollowStatus::Applied) f.follow_applied = Tri::True;
            else if (f.follow_applied == Tri::Unknown && fs != FollowStatus::NotOpen) f.follow_applied = Tri::False;
        }
    }
    DoorSample s = bridge_.sample(o.door_ref);
    if (auto r = scope_lost(host)) return r;
    if (!s.readable) return std::nullopt;   // no fresh fact: prior facts stand, nothing is promoted
    if (s.opened == Tri::True) {
        f.opened = Tri::True;
        if (s.opened_side == Side::A || s.opened_side == Side::B) f.opened_side = s.opened_side;
    }
    if (s.motion_layer == Tri::True) f.motion_layer = Tri::True;
    if (s.value && std::isfinite(*s.value)) {
        float v = *s.value;
        ++f.readable_samples;
        // A value is only comparable with a baseline measured on the same PeekedWork side.
        // When that identity becomes known or changes, re-acquire: a side switch alone
        // never proves leaf motion (adapter review 1328 finding 4).
        if (!o.baseline || s.value_side != o.baseline_side) {
            if (o.baseline) ++counters_.baseline_resets;
            o.baseline = v;
            o.baseline_side = s.value_side;
        } else {
            float delta = std::fabs(v - *o.baseline);
            f.max_delta = std::max(f.max_delta, delta);
            if (delta >= cfg_.progress_threshold) f.progress = Tri::True;
        }
    }
    if (!host) return std::nullopt;
    if (!o.apply_sent && f.opened == Tri::True && f.opened_side != Side::Unknown) {
        if (!send(ApplyMsg{o.view.fence, o.view.op, o.view.req, o.door, f.opened_side})) return std::nullopt;
        o.apply_sent = true;
        log(now, "apply_sent", to_string(f.opened_side));
        if (auto r = scope_lost(true)) return r;
    }
    if (o.apply_sent && s.value && o.progress_n < cfg_.max_progress_samples &&
        (o.progress_n == 0 || now - o.last_progress_ms >= cfg_.progress_interval_ms)) {
        if (auto wv = WireValue::from(*s.value)) {
            if (!send(ProgressMsg{o.view.fence, o.view.op, o.progress_n + 1, *wv})) return std::nullopt;
            ++o.progress_n;
            o.last_progress_ms = now;
            if (auto r = scope_lost(true)) return r;
        } else {
            log(now, "value_unrepresentable");
        }
    }
    if (o.start_side != Side::Unknown) {
        Side cur = bridge_.actor_side(o.actor_ref, o.door_ref);
        if (auto r = scope_lost(true)) return r;
        if (cur != Side::Unknown && cur != o.start_side) f.crossed = Tri::True;
    }
    return std::nullopt;
}

bool DoorCore::send(const Message& m) {
    std::string err;
    if (!encode(m, &err)) {               // never emit a contract-invalid message
        ++counters_.invalid_outbound;
        log(last_now_, "invalid_outbound", std::string(type_name(m)) + " " + err);
        if (op_) op_->invalid_outbound = true;
        return false;
    }
    if (transport_.send(m)) return true;
    ++counters_.send_failures;
    log(last_now_, "send_failed", type_name(m));
    if (op_) op_->overflow = true;
    return false;
}

void DoorCore::set_phase(DoorPhase p, Reason r, uint64_t now, const char* event) {
    Op& o = *op_;
    o.view.phase = p;
    o.view.reason = r;
    send(StatusMsg{o.view.fence, o.view.op, o.view.req, o.view.role, p, r});
    log(now, event);
}

void DoorCore::finish(DoorPhase p, Reason r, uint64_t now, const char* event) {
    Op& o = *op_;
    auto& f = o.view.facts;
    fold_eligibility();
    drop_lease();   // before any message: the lease never outlives its operation
    // Unknown stays Unknown unless at least one readable post-write sample exists.
    if (f.engine_entered == Tri::True && f.progress == Tri::Unknown && f.readable_samples > 0) f.progress = Tri::False;
    o.view.phase = p;
    o.view.reason = r;
    o.view.final = true;
    bool keep_overflow = o.overflow, keep_invalid = o.invalid_outbound;
    if (o.view.role == Role::Guest) {   // the peer claim goes out first, right after the decision
        ResultMsg rm{o.view.fence, o.view.op, p, r, f.opened, f.progress};
        results_.push_back({o.view.op, rm});
        if (results_.size() > 16) results_.erase(results_.begin());
        o.result_recorded = true;
        send(rm);
        o.result_sent = true;   // after the call: a throw inside it re-sends (duplicate) rather than loses
    }
    send(StatusMsg{o.view.fence, o.view.op, o.view.req, o.view.role, p, r});
    o.status_sent = true;
    o.overflow = keep_overflow;
    o.invalid_outbound = keep_invalid;
    finished_.push_back(o.view);
    OpView done = o.view;
    op_.reset();
    // Logged after the operation has left: a journal callback cannot observe or
    // re-enter a half-finished operation.
    JournalRecord rec;
    rec.ms = now;
    rec.role = done.role;
    rec.connection = done.fence.connection;
    rec.op = done.op;
    rec.req = done.req;
    rec.event = event;
    rec.phase = done.phase;
    rec.reason = done.reason;
    journal_.write(rec);
}

void DoorCore::refuse_status(const Fence& f, uint64_t req, Reason r, uint64_t now) {
    if (f.valid()) send(StatusMsg{f, 0, req, session_.role, DoorPhase::Blocked, r});
    JournalRecord rec;
    rec.ms = now;
    rec.connection = f.connection;
    rec.req = req;
    rec.role = session_.role;
    rec.event = "intent_refused";
    rec.phase = DoorPhase::Blocked;
    rec.reason = r;
    journal_.write(rec);
}

void DoorCore::log(uint64_t now, const char* event, const std::string& detail) {
    JournalRecord rec;
    rec.ms = now;
    rec.role = op_ ? op_->view.role : session_.role;
    rec.connection = op_ ? op_->view.fence.connection : session_.fence.connection;
    rec.op = op_ ? op_->view.op : 0;
    rec.req = op_ ? op_->view.req : 0;
    rec.event = event;
    rec.phase = op_ ? op_->view.phase : DoorPhase::None;
    rec.reason = op_ ? op_->view.reason : Reason::None;
    rec.detail = detail;
    journal_.write(rec);
}

}  // namespace re2net::core
