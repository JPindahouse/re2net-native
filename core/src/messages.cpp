// Strict codec for contract re2net.door v1. Hand-written on purpose: the accepted
// grammar is a tiny subset of JSON (one flat object; string, non-negative integer and
// boolean values; no escapes, no nesting, no floats, no null), which keeps the
// validator identical on the C++ and Python sides and makes every rejection explicit.
// The same rules are enforced on encode, so an invalid value can never be emitted.
#include "re2net/core/messages.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <map>
#include <set>
#include <string_view>

namespace re2net::core {
namespace {

constexpr uint64_t kMaxInt = 9007199254740991ull;  // 2^53-1, exact in Python/JSON
constexpr size_t kMaxKeys = 24;

struct Value {
    enum Kind { Str, Int, Bool } kind = Str;
    std::string s;
    uint64_t i = 0;
    bool b = false;
};
using Object = std::map<std::string, Value, std::less<>>;

// ---------------------------------------------------------------- parser
struct Parser {
    std::string_view t;
    size_t p = 0;
    std::string err;
    void ws() { while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\r' || t[p] == '\n')) ++p; }
    bool fail(const char* e) { if (err.empty()) err = e; return false; }
    bool str(std::string& out) {
        if (p >= t.size() || t[p] != '"') return fail("expected_string");
        ++p;
        size_t start = p;
        while (p < t.size() && t[p] != '"') {
            unsigned char c = static_cast<unsigned char>(t[p]);
            if (c == '\\' || c < 0x20 || c > 0x7e) return fail("string_char");
            ++p;
        }
        if (p >= t.size()) return fail("unterminated_string");
        out.assign(t.substr(start, p - start));
        ++p;
        if (out.size() > kMaxToken) return fail("string_too_long");
        return true;
    }
    bool value(Value& v) {
        if (p >= t.size()) return fail("expected_value");
        char c = t[p];
        if (c == '"') { v.kind = Value::Str; return str(v.s); }
        if (c >= '0' && c <= '9') {
            size_t start = p;
            while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p;
            std::string_view num = t.substr(start, p - start);
            if (num.size() > 1 && num[0] == '0') return fail("leading_zero");
            if (p < t.size() && (t[p] == '.' || t[p] == 'e' || t[p] == 'E')) return fail("float_not_allowed");
            uint64_t x = 0;
            auto r = std::from_chars(num.data(), num.data() + num.size(), x);
            if (r.ec != std::errc{} || x > kMaxInt) return fail("int_range");
            v.kind = Value::Int; v.i = x;
            return true;
        }
        if (t.substr(p, 4) == "true") { p += 4; v.kind = Value::Bool; v.b = true; return true; }
        if (t.substr(p, 5) == "false") { p += 5; v.kind = Value::Bool; v.b = false; return true; }
        return fail("value_kind");
    }
    bool object(Object& o) {
        ws();
        if (p >= t.size() || t[p] != '{') return fail("expected_object");
        ++p; ws();
        if (p < t.size() && t[p] == '}') { ++p; ws(); return p == t.size() ? true : fail("trailing_data"); }
        for (;;) {
            ws();
            std::string k;
            if (!str(k)) return false;
            ws();
            if (p >= t.size() || t[p] != ':') return fail("expected_colon");
            ++p; ws();
            Value v;
            if (!value(v)) return false;
            if (!o.emplace(std::move(k), std::move(v)).second) return fail("duplicate_key");
            if (o.size() > kMaxKeys) return fail("too_many_keys");
            ws();
            if (p < t.size() && t[p] == ',') { ++p; continue; }
            if (p < t.size() && t[p] == '}') { ++p; break; }
            return fail("expected_comma_or_brace");
        }
        ws();
        if (p != t.size()) return fail("trailing_data");
        return true;
    }
};

// ---------------------------------------------------------------- tables
constexpr std::array<std::pair<const char*, Tri>, 3> kTri{{
    {"unknown", Tri::Unknown}, {"false", Tri::False}, {"true", Tri::True}}};
constexpr std::array<std::pair<const char*, Role>, 3> kRole{{
    {"none", Role::None}, {"host", Role::Host}, {"guest", Role::Guest}}};
constexpr std::array<std::pair<const char*, ActorRole>, 2> kActor{{
    {"p1", ActorRole::P1}, {"p2", ActorRole::P2}}};
constexpr std::array<std::pair<const char*, Side>, 2> kSide{{
    {"a", Side::A}, {"b", Side::B}}};   // Unknown is not representable on the wire
constexpr std::array<std::pair<const char*, DoorPhase>, 9> kPhase{{
    {"none", DoorPhase::None}, {"opening", DoorPhase::Opening},
    {"waiting_partner_scene", DoorPhase::WaitingPartnerScene}, {"open_both", DoorPhase::OpenBoth},
    {"open_both_partner_crossed_host", DoorPhase::OpenBothPartnerCrossedHost},
    {"blocked", DoorPhase::Blocked}, {"interrupted", DoorPhase::Interrupted},
    {"uncertain", DoorPhase::Uncertain}, {"mismatch", DoorPhase::Mismatch}}};

const std::array<std::pair<const char*, Reason>, kReasonCount>& reason_table() {
    static const std::array<std::pair<const char*, Reason>, kReasonCount> t = [] {
        std::array<std::pair<const char*, Reason>, kReasonCount> a{};
        for (int i = 0; i < kReasonCount; ++i) a[i] = {to_string(static_cast<Reason>(i)), static_cast<Reason>(i)};
        return a;
    }();
    return t;
}

template <class E, size_t N>
const char* name_of(E e, const std::array<std::pair<const char*, E>, N>& table) {
    for (auto& [n, v] : table) if (v == e) return n;
    return nullptr;   // not representable: encode refuses
}

// ---------------------------------------------------------------- reader
struct Reader {
    const Object& o;
    std::set<std::string, std::less<>> seen;
    std::string err;
    bool fail(const std::string& e) { if (err.empty()) err = e; return false; }
    const Value* get(std::string_view k, Value::Kind kind) {
        auto it = o.find(k);
        if (it == o.end()) { fail("missing_" + std::string(k)); return nullptr; }
        if (it->second.kind != kind) { fail("type_" + std::string(k)); return nullptr; }
        seen.emplace(k);
        return &it->second;
    }
    bool u64(std::string_view k, uint64_t& out, uint64_t lo = 0, uint64_t hi = kMaxInt) {
        auto v = get(k, Value::Int);
        if (!v) return false;
        if (v->i < lo || v->i > hi) return fail("range_" + std::string(k));
        out = v->i;
        return true;
    }
    bool u32(std::string_view k, uint32_t& out, uint32_t lo = 0, uint32_t hi = 0xffffffffu) {
        uint64_t x = 0;
        if (!u64(k, x, lo, hi)) return false;
        out = static_cast<uint32_t>(x);
        return true;
    }
    bool boolean(std::string_view k, bool& out) {
        auto v = get(k, Value::Bool);
        if (!v) return false;
        out = v->b;
        return true;
    }
    bool token(std::string_view k, std::string& out, size_t max_len) {
        auto v = get(k, Value::Str);
        if (!v) return false;
        if (!valid_token(v->s, max_len)) return fail("token_" + std::string(k));
        out = v->s;
        return true;
    }
    template <class E, size_t N>
    bool enumv(std::string_view k, E& out, const std::array<std::pair<const char*, E>, N>& table) {
        auto v = get(k, Value::Str);
        if (!v) return false;
        for (auto& [name, e] : table) if (v->s == name) { out = e; return true; }
        return fail("enum_" + std::string(k));
    }
    bool exact_keys() {
        for (auto& [k, v] : o) if (!seen.count(k)) return fail("unknown_key_" + k);
        return true;
    }
    bool fence(Fence& f) {
        return token("conn", f.connection, kMaxToken) && token("bar", f.barrier, kMaxToken) &&
               token("hb", f.host_boot, kMaxBoot) && token("gb", f.guest_boot, kMaxBoot) &&
               u32("loc", f.scene_location) && u32("room", f.scene_room);
    }
    bool door(DoorKey& d, const char* nk, const char* lk, const char* rk) {
        return token(nk, d.name, kMaxDoorName) && u32(lk, d.location) && u32(rk, d.room);
    }
    bool value(WireValue& v) {
        return u32("vmil", v.milli, 0, kMaxValueMilli) && boolean("vneg", v.negative);
    }
};

// ---------------------------------------------------------------- writer
struct Writer {
    std::string s{"{\"v\":1"};
    std::string err;
    bool fail(const std::string& e) { if (err.empty()) err = e; return false; }
    bool ok() const { return err.empty(); }
    Writer& str(const char* k, std::string_view v) { s += ",\""; s += k; s += "\":\""; s += v; s += '"'; return *this; }
    Writer& num(const char* k, uint64_t v) { s += ",\""; s += k; s += "\":"; s += std::to_string(v); return *this; }
    Writer& b(const char* k, bool v) { s += ",\""; s += k; s += "\":"; s += v ? "true" : "false"; return *this; }
    Writer& token(const char* k, const std::string& v, size_t max_len) {
        if (!valid_token(v, max_len)) fail(std::string("token_") + k);
        return str(k, v);
    }
    template <class E, size_t N>
    Writer& enumv(const char* k, E e, const std::array<std::pair<const char*, E>, N>& table) {
        const char* n = name_of(e, table);
        if (!n) { fail(std::string("enum_") + k); return *this; }
        return str(k, n);
    }
    Writer& id(const char* k, uint64_t v, uint64_t lo = 1, uint64_t hi = kMaxInt) {
        if (v < lo || v > hi) fail(std::string("range_") + k);
        return num(k, v);
    }
    Writer& fence(const Fence& f) {
        token("conn", f.connection, kMaxToken).token("bar", f.barrier, kMaxToken)
            .token("hb", f.host_boot, kMaxBoot).token("gb", f.guest_boot, kMaxBoot);
        return num("loc", f.scene_location).num("room", f.scene_room);
    }
    Writer& door(const DoorKey& d, const char* nk, const char* lk, const char* rk) {
        return token(nk, d.name, kMaxDoorName).num(lk, d.location).num(rk, d.room);
    }
    Writer& value(const WireValue& v) {
        if (v.milli > kMaxValueMilli) fail("range_vmil");
        return num("vmil", v.milli).b("vneg", v.negative);
    }
};

}  // namespace

std::optional<WireValue> WireValue::from(float v) {
    if (!std::isfinite(v)) return std::nullopt;
    double m = std::fabs(static_cast<double>(v)) * 1000.0;
    if (m > kMaxValueMilli) return std::nullopt;
    WireValue w;
    w.milli = static_cast<uint32_t>(std::llround(m));
    w.negative = v < 0 && w.milli != 0;
    return w;
}

const char* type_name(const Message& m) {
    static const char* names[] = {"session", "door_intent", "door_cancel", "door_select", "door_select_ack",
                                  "door_apply", "door_progress", "door_host_done", "door_result",
                                  "door_status", "caps"};
    return names[m.index()];
}

bool is_peer_message(const Message& m) {
    return std::holds_alternative<SelectMsg>(m) || std::holds_alternative<SelectAckMsg>(m) ||
           std::holds_alternative<ApplyMsg>(m) || std::holds_alternative<ProgressMsg>(m) ||
           std::holds_alternative<HostDoneMsg>(m) || std::holds_alternative<ResultMsg>(m);
}

std::optional<std::string> encode(const Message& m, std::string* error) {
    Writer w;
    w.str("t", type_name(m));
    std::visit([&](auto&& x) {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, SessionMsg>) {
            w.fence(x.fence).enumv("role", x.role, kRole).b("conn_up", x.connected)
             .b("consent", x.consent).b("playing", x.playing);
        } else if constexpr (std::is_same_v<T, IntentMsg>) {
            w.fence(x.fence).id("req", x.req).door(x.door, "door", "dloc", "droom").enumv("actor", x.actor, kActor);
        } else if constexpr (std::is_same_v<T, CancelMsg>) {
            w.fence(x.fence).id("op", x.op);
        } else if constexpr (std::is_same_v<T, SelectMsg>) {
            w.fence(x.fence).token("impl", x.impl, kMaxBoot);
        } else if constexpr (std::is_same_v<T, SelectAckMsg>) {
            w.fence(x.fence).token("impl", x.impl, kMaxBoot).b("ok", x.ok).enumv("reason", x.reason, reason_table());
        } else if constexpr (std::is_same_v<T, ApplyMsg>) {
            w.fence(x.fence).id("op", x.op).id("req", x.req).door(x.door, "door", "dloc", "droom")
             .enumv("side", x.side, kSide);
        } else if constexpr (std::is_same_v<T, ProgressMsg>) {
            w.fence(x.fence).id("op", x.op).id("n", x.n, 1, 1000).value(x.value);
        } else if constexpr (std::is_same_v<T, HostDoneMsg>) {
            w.fence(x.fence).id("op", x.op).enumv("progress", x.progress, kTri)
             .enumv("crossed", x.crossed, kTri).enumv("reason", x.reason, reason_table());
        } else if constexpr (std::is_same_v<T, ResultMsg>) {
            w.fence(x.fence).id("op", x.op).enumv("phase", x.phase, kPhase).enumv("reason", x.reason, reason_table())
             .enumv("opened", x.opened, kTri).enumv("progress", x.progress, kTri);
        } else if constexpr (std::is_same_v<T, StatusMsg>) {
            w.fence(x.fence).id("op", x.op, 0).id("req", x.req, 0).enumv("role", x.role, kRole)
             .enumv("phase", x.phase, kPhase).enumv("reason", x.reason, reason_table());
        } else if constexpr (std::is_same_v<T, CapsMsg>) {
            w.b("ok", x.ok).id("core_version", x.core_version, 1, 1).token("impl", x.impl, kMaxBoot);
        }
    }, m);
    std::string out = w.s + "}";
    if (w.ok() && out.size() > kMaxMessageBytes) w.fail("too_large");
    if (!w.ok()) {
        if (error) *error = w.err;
        return std::nullopt;
    }
    return out;
}

std::optional<Message> decode(std::string_view text, std::string* error) {
    auto bad = [&](std::string e) -> std::optional<Message> {
        if (error) *error = std::move(e);
        return std::nullopt;
    };
    if (text.size() > kMaxMessageBytes) return bad("too_large");
    Parser ps{text};
    Object o;
    if (!ps.object(o)) return bad(ps.err);
    Reader r{o};
    uint64_t v = 0;
    std::string t;
    if (!r.u64("v", v, 1, 1)) return bad(r.err);
    if (!r.token("t", t, 32)) return bad(r.err);

    std::optional<Message> out;
    if (t == "session") {
        SessionMsg m;
        if (r.fence(m.fence) && r.enumv("role", m.role, kRole) && r.boolean("conn_up", m.connected) &&
            r.boolean("consent", m.consent) && r.boolean("playing", m.playing))
            out = m;
    } else if (t == "door_intent") {
        IntentMsg m;
        if (r.fence(m.fence) && r.u64("req", m.req, 1) && r.door(m.door, "door", "dloc", "droom") &&
            r.enumv("actor", m.actor, kActor))
            out = m;
    } else if (t == "door_cancel") {
        CancelMsg m;
        if (r.fence(m.fence) && r.u64("op", m.op, 1)) out = m;
    } else if (t == "door_select") {
        SelectMsg m;
        if (r.fence(m.fence) && r.token("impl", m.impl, kMaxBoot)) out = m;
    } else if (t == "door_select_ack") {
        SelectAckMsg m;
        if (r.fence(m.fence) && r.token("impl", m.impl, kMaxBoot) && r.boolean("ok", m.ok) &&
            r.enumv("reason", m.reason, reason_table()))
            out = m;
    } else if (t == "door_apply") {
        ApplyMsg m;
        if (r.fence(m.fence) && r.u64("op", m.op, 1) && r.u64("req", m.req, 1) &&
            r.door(m.door, "door", "dloc", "droom") && r.enumv("side", m.side, kSide))
            out = m;
    } else if (t == "door_progress") {
        ProgressMsg m;
        if (r.fence(m.fence) && r.u64("op", m.op, 1) && r.u32("n", m.n, 1, 1000) && r.value(m.value))
            out = m;
    } else if (t == "door_host_done") {
        HostDoneMsg m;
        if (r.fence(m.fence) && r.u64("op", m.op, 1) && r.enumv("progress", m.progress, kTri) &&
            r.enumv("crossed", m.crossed, kTri) && r.enumv("reason", m.reason, reason_table()))
            out = m;
    } else if (t == "door_result") {
        ResultMsg m;
        if (r.fence(m.fence) && r.u64("op", m.op, 1) && r.enumv("phase", m.phase, kPhase) &&
            r.enumv("reason", m.reason, reason_table()) && r.enumv("opened", m.opened, kTri) &&
            r.enumv("progress", m.progress, kTri))
            out = m;
    } else if (t == "door_status") {
        StatusMsg m;
        if (r.fence(m.fence) && r.u64("op", m.op) && r.u64("req", m.req) && r.enumv("role", m.role, kRole) &&
            r.enumv("phase", m.phase, kPhase) && r.enumv("reason", m.reason, reason_table()))
            out = m;
    } else if (t == "caps") {
        CapsMsg m;
        uint64_t ver = 0;
        if (r.boolean("ok", m.ok) && r.u64("core_version", ver, 1, 1) && r.token("impl", m.impl, kMaxBoot)) {
            m.core_version = static_cast<uint32_t>(ver);
            out = m;
        }
    } else {
        return bad("unknown_type");
    }
    if (!out) return bad(r.err.empty() ? "invalid" : r.err);
    if (!r.exact_keys()) return bad(r.err);
    return out;
}

}  // namespace re2net::core
