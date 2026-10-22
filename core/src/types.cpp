#include "re2net/core/types.hpp"

namespace re2net::core {

bool valid_token(const std::string& s, size_t max_len) {
    if (s.empty() || s.size() > max_len) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '-' || c == '.' || c == ':';
        if (!ok) return false;
    }
    return true;
}

const char* to_string(Tri t) {
    switch (t) {
        case Tri::False: return "false";
        case Tri::True: return "true";
        default: return "unknown";
    }
}

const char* to_string(Role r) {
    switch (r) {
        case Role::Host: return "host";
        case Role::Guest: return "guest";
        default: return "none";
    }
}

const char* to_string(Side s) {
    switch (s) {
        case Side::A: return "a";
        case Side::B: return "b";
        default: return "unknown";
    }
}

const char* to_string(DoorPhase p) {
    switch (p) {
        case DoorPhase::Opening: return "opening";
        case DoorPhase::WaitingPartnerScene: return "waiting_partner_scene";
        case DoorPhase::OpenBoth: return "open_both";
        case DoorPhase::OpenBothPartnerCrossedHost: return "open_both_partner_crossed_host";
        case DoorPhase::Blocked: return "blocked";
        case DoorPhase::Interrupted: return "interrupted";
        case DoorPhase::Uncertain: return "uncertain";
        case DoorPhase::Mismatch: return "mismatch";
        default: return "none";
    }
}

const char* to_string(Reason r) {
    switch (r) {
        case Reason::None: return "none";
        case Reason::NotPlaying: return "not_playing";
        case Reason::NoConsent: return "no_consent";
        case Reason::Disconnected: return "disconnected";
        case Reason::FenceChanged: return "fence_changed";
        case Reason::SceneMismatch: return "scene_mismatch";
        case Reason::SceneTimeout: return "scene_timeout";
        case Reason::DoorMissing: return "door_missing";
        case Reason::DoorDuplicate: return "door_duplicate";
        case Reason::DoorNotLoaded: return "door_not_loaded";
        case Reason::DoorLocked: return "door_locked";
        case Reason::LockUnknown: return "lock_unknown";
        case Reason::AlreadyOpen: return "already_open";
        case Reason::ActorMissing: return "actor_missing";
        case Reason::HostFar: return "host_far";
        case Reason::DistanceUnknown: return "distance_unknown";
        case Reason::Unsupported: return "unsupported";
        case Reason::NativeFalse: return "native_false";
        case Reason::NativeException: return "native_exception";
        case Reason::NestedCall: return "nested_call";
        case Reason::Stale: return "stale";
        case Reason::Cancelled: return "cancelled";
        case Reason::Overflow: return "overflow";
        case Reason::Duplicate: return "duplicate";
        case Reason::OutOfOrder: return "out_of_order";
        case Reason::GuestTimeout: return "guest_timeout";
        case Reason::NoProgress: return "no_progress";
        case Reason::Busy: return "busy";
        case Reason::BadMessage: return "bad_message";
        case Reason::NotSelected: return "not_selected";
        case Reason::NoOpenMutation: return "no_open_mutation";
        case Reason::InvalidOutbound: return "invalid_outbound";
        case Reason::RoleChanged: return "role_changed";
        case Reason::ConsentLost: return "consent_lost";
        case Reason::Count_: break;
    }
    return "none";
}

}  // namespace re2net::core
