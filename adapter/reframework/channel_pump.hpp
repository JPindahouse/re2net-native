// ChannelPump: per-engine-callback bridge from the local channel to DoorCore.
// Header-only and free of Windows/REFramework types so the exact plugin logic is tested
// offline against a fake channel (tests/test_adapter.cpp).
//
// Local connection identity (pipe review 1328 finding 1): EVERY local epoch change,
// observed or not, and whether or not the client is connected again by now, ends all
// local authority in the core (DoorCore::local_reset). A new connection receives caps
// first and must send a fresh session before anything acts.
//
// Local-channel refusal and epoch rules:
//  - Poisoned epoch: a local connection that delivered an undecodable frame, or whose
//    frame the core inbox lost, is refused from that moment: its remaining and later
//    frames are discarded (no same-epoch re-grant, in this batch or a later callback),
//    until the channel reaches a STRICTLY newer real epoch. The drop is requested from
//    the worker, but safety never waits for it. The reservation is untouched (no
//    fallback on ambiguity).
//  - After-take race: the worker may disconnect/reconnect after take_in releases its
//    lock. Failed/epoch/connected are re-read after the snapshot; only frames of the
//    exact current live connection are accepted, and the epoch is checked once more
//    right before tick. live() is also the core's engine-boundary fence
//    (DoorCore::set_local_fence), checked immediately before every engine write. No check
//    can cancel an engine call that has already been entered.
#pragma once
#include <cstdint>
#include "re2net/core/door_core.hpp"

namespace re2net::adapter {

template <class Channel>
struct ChannelPump {
    uint64_t seen_epoch = 0;        // the local connection whose frames are accepted
    uint64_t poisoned_epoch = 0;    // refused through this epoch (0 = none)
    uint64_t stale_frames = 0;      // frames of a connection that is no longer the live one
    uint64_t poisoned_frames = 0;   // frames of a poisoned connection, discarded
    uint64_t resets = 0;            // local authority resets
    uint64_t rejected_text = 0;     // undecodable local frames
    uint64_t late_epoch_changes = 0;  // epoch moved after the initial sample (after take / before tick)
    bool failure_seen = false;

    // The current local connection may act: not failed, connected, the adopted epoch, not poisoned.
    bool live(const Channel& ch) const {
        return !failure_seen && !ch.failed() && ch.connected() && ch.connection_epoch() == seen_epoch &&
               seen_epoch > poisoned_epoch;
    }

    void step(Channel& ch, core::DoorCore& core, core::Transport& caps_out, uint64_t now) {
        if (failed(ch, core)) { core.tick(now); return; }
        adopt(ch, core, caps_out, ch.connection_epoch());
        auto frames = ch.take_in();
        if (failed(ch, core)) { stale_frames += frames.size(); core.tick(now); return; }
        uint64_t current = ch.connection_epoch();
        if (current != seen_epoch) { ++late_epoch_changes; adopt(ch, core, caps_out, current); }
        const bool up = ch.connected();
        for (auto& f : frames) {
            if (!up || f.epoch != seen_epoch) { ++stale_frames; continue; }
            if (seen_epoch <= poisoned_epoch) { ++poisoned_frames; continue; }
            if (!core.receive_text(f.line)) { ++rejected_text; poison(ch, core, seen_epoch, "bad_local_frame"); }
        }
        if (core.take_local_loss()) poison(ch, core, seen_epoch, "local_inbox_loss");
        // Last look before the core can reach the engine this callback.
        if (!failed(ch, core) && ch.connection_epoch() != seen_epoch) {
            ++late_epoch_changes;
            adopt(ch, core, caps_out, ch.connection_epoch());
        }
        core.tick(now);
    }

private:
    bool failed(Channel& ch, core::DoorCore& core) {
        if (!ch.failed() && !failure_seen) return false;
        if (!failure_seen) { failure_seen = true; ++resets; core.local_reset("channel_failed"); }
        return true;
    }
    void poison(Channel& ch, core::DoorCore& core, uint64_t epoch, const char* why) {
        if (poisoned_epoch < epoch) poisoned_epoch = epoch;
        ++resets;
        core.local_reset(why);
        ch.drop_client(epoch);   // asynchronous; safety does not depend on it
    }
    void adopt(Channel& ch, core::DoorCore& core, core::Transport& caps_out, uint64_t epoch) {
        if (epoch == seen_epoch) return;
        seen_epoch = epoch;
        ++resets;
        core.local_reset("local_epoch_changed");
        if (epoch > poisoned_epoch && ch.connected() && ch.connection_epoch() == epoch) caps_out.send(core.caps());
    }
};

}  // namespace re2net::adapter
