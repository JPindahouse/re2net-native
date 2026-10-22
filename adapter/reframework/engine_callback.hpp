// The plugin's engine-callback failure boundary and the retained eligibility hook's
// authority (R1446 static review finding 3). Header-only so the offline tests compile the
// exact code plugin_main.cpp runs. No REFramework or Windows dependency.
#pragma once
#include "re2net/core/engine_bridge.hpp"

namespace re2net::adapter {

// The hook permit for the exact leased (door, actor) refs: the plugin is not blocked AND
// the core's CURRENT operation holds exactly this lease with its full pure-state write
// permission (DoorCore::lease_permit, which includes the local connection fence). Channel
// health alone is never enough, and anything missing is a refusal: there is no healthy
// default to fall back to.
template <class Core>
bool retained_hook_permit(const bool& blocked, const Core* core, core::ObjRef door, core::ObjRef actor) {
    return !blocked && core != nullptr && core->lease_permit(door, actor);
}

// One engine callback body. A C++ exception blocks the plugin (later callbacks return at
// once) AND, when it happened on the engine owner thread, retires the core's lease now,
// state-only, because no later tick will run to do it. Off the owner thread nothing is
// cleaned up here; the blocked flag alone already refuses every hook (see above).
template <class Core, class OnOwner, class Body>
void run_engine_callback(bool& blocked, Core* core, OnOwner&& on_owner_thread, Body&& body) noexcept {
    if (blocked) return;
    try {
        body();
    } catch (...) {
        blocked = true;
        try {
            if (core && on_owner_thread()) core->abandon_lease();
        } catch (...) {
        }
    }
}

}  // namespace re2net::adapter
