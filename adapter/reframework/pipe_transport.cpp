#include "pipe_transport.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

namespace re2net::adapter {
namespace {
// Security descriptor granting full access to the current user only (object ACL of
// our own pipe; no system or policy setting is touched).
bool current_user_sa(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& sd) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    std::vector<unsigned char> buf(len);
    bool ok = len && GetTokenInformation(tok, TokenUser, buf.data(), len, &len);
    CloseHandle(tok);
    if (!ok) return false;
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &sid)) return false;
    std::wstring sddl = L"D:P(A;;GA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return false;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    return true;
}
}  // namespace

// Everything the system may still write into while an operation is pending.
struct LocalChannel::Io {
    OVERLAPPED conn{}, read{}, write{};
    char rbuf[4096]{};
    std::string wframe;
    std::string partial;
    bool listening = false, reading = false, writing = false, discard_line = false;
};

LocalChannel::LocalChannel() = default;

LocalChannel::~LocalChannel() {
    if (worker_.joinable()) {   // orderly teardown only (see header)
        request_stop();
        worker_.join();
        // The worker closed its own Io events and the pipe (or deliberately leaked them
        // with failed()); the stop/wake events are ours. A failed worker keeps them too.
        if (!failed_.load()) {
            if (stop_event_) { CloseHandle(static_cast<HANDLE>(stop_event_)); stop_event_ = nullptr; }
            if (wake_event_) { CloseHandle(static_cast<HANDLE>(wake_event_)); wake_event_ = nullptr; }
        }
    }
}

bool LocalChannel::start(const std::wstring& pipe_name, const std::wstring& journal_path, std::string& why) {
    pipe_name_ = pipe_name;
    journal_path_ = journal_path;
    auto io = std::make_unique<Io>();
    io->wframe.reserve(kMaxFrame + 1);
    io->partial.reserve(kMaxFrame);
    auto close_all = [&] {
        for (HANDLE h : {io->conn.hEvent, io->read.hEvent, io->write.hEvent, static_cast<HANDLE>(stop_event_),
                         static_cast<HANDLE>(wake_event_)})
            if (h) CloseHandle(h);
        if (pipe_) CloseHandle(static_cast<HANDLE>(pipe_));
        stop_event_ = wake_event_ = pipe_ = nullptr;
    };
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    wake_event_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    io->conn.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    io->read.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    io->write.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_event_ || !wake_event_ || !io->conn.hEvent || !io->read.hEvent || !io->write.hEvent) {
        why = "event_create_failed";
        close_all();
        return false;
    }
    if (!create_instance()) {
        why = "pipe_create_failed_" + std::to_string(GetLastError());
        close_all();
        return false;
    }
    io_ = std::move(io);
    try {
        worker_ = std::thread([this] { run(); });   // last: nothing after this can fail
    } catch (...) {
        why = "thread_start_failed";
        io = std::move(io_);
        close_all();
        return false;
    }
    return true;
}

bool LocalChannel::create_instance() {
    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!current_user_sa(sa, sd)) return false;
    HANDLE h = CreateNamedPipeW(pipe_name_.c_str(),
                                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                1, 64 * 1024, 64 * 1024, 0, &sa);
    LocalFree(sd);
    if (h == INVALID_HANDLE_VALUE) return false;
    pipe_ = h;
    return true;
}

void LocalChannel::request_stop() {
    if (stop_event_) SetEvent(static_cast<HANDLE>(stop_event_));
}

bool LocalChannel::push_out(const std::string& frame, uint64_t epoch) {
    std::lock_guard<std::mutex> g(mu_);
    if (!connected_.load() || epoch != epoch_.load() || out_.size() >= kOutCap || frame.size() > kMaxFrame) {
        ++counters_.out_refused;
        return false;
    }
    out_.push_back(frame);
    SetEvent(static_cast<HANDLE>(wake_event_));
    return true;
}

bool LocalChannel::push_journal(const std::string& line) {
    std::lock_guard<std::mutex> g(mu_);
    if (journal_.size() >= kJournalCap || line.size() > kMaxJournalLine) { ++counters_.journal_dropped; return false; }
    journal_.push_back(line);
    SetEvent(static_cast<HANDLE>(wake_event_));
    return true;
}

void LocalChannel::note(const char* event, const std::string& detail) {
    std::string line = "{\"ms\":" + std::to_string(GetTickCount64()) + ",\"src\":\"channel\",\"event\":\"" + event +
                       "\",\"epoch\":" + std::to_string(epoch_.load()) + ",\"detail\":\"" + detail.substr(0, 120) + "\"}";
    push_journal(line);
}

std::vector<InFrame> LocalChannel::take_in() {
    std::lock_guard<std::mutex> g(mu_);
    std::vector<InFrame> v(std::make_move_iterator(in_.begin()), std::make_move_iterator(in_.end()));
    in_.clear();
    return v;
}

void LocalChannel::drop_client(uint64_t epoch) {
    drop_epoch_ = epoch;
    if (wake_event_) SetEvent(static_cast<HANDLE>(wake_event_));
}

ChannelCounters LocalChannel::counters() {
    std::lock_guard<std::mutex> g(mu_);
    return counters_;
}

// Bounded, best-effort diagnostics (finding 5): bounded line bytes, bounded file size,
// at most kJournalBatch lines per iteration so control I/O stays responsive, flushed at
// most once a second and at shutdown. A failed or partial write counts as dropped. Tails
// still queued at process exit can be lost: this is not campaign-grade recording.
void LocalChannel::flush_journal(bool force) {
    std::deque<std::string> batch;
    {
        std::lock_guard<std::mutex> g(mu_);
        size_t n = force ? journal_.size() : std::min(journal_.size(), kJournalBatch);
        for (size_t i = 0; i < n; ++i) { batch.push_back(std::move(journal_.front())); journal_.pop_front(); }
        if (!journal_.empty()) SetEvent(static_cast<HANDLE>(wake_event_));   // come back for the rest
    }
    uint64_t initial_bytes = 0;
    bool opened_now = false;
    if (!batch.empty() && !journal_file_) {
        // Exclusive per-instance file (the name carries pid + boot tick). If one with that
        // name already exists, append to it but count its existing length against the cap.
        HANDLE f = CreateFileW(journal_path_.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
            f = CreateFileW(journal_path_.c_str(), FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            LARGE_INTEGER size{};
            if (f != INVALID_HANDLE_VALUE && GetFileSizeEx(f, &size)) initial_bytes = static_cast<uint64_t>(size.QuadPart);
            else if (f != INVALID_HANDLE_VALUE) { CloseHandle(f); f = INVALID_HANDLE_VALUE; }   // unknown size: no journal
        }
        if (f != INVALID_HANDLE_VALUE) { journal_file_ = f; opened_now = true; }
    }
    HANDLE f = static_cast<HANDLE>(journal_file_);
    uint64_t written = 0, dropped = 0, errors = 0, bytes = 0;
    {
        std::lock_guard<std::mutex> g(mu_);
        if (opened_now) counters_.journal_bytes = initial_bytes;
        bytes = counters_.journal_bytes;
    }
    static const std::string kCapMark = "{\"src\":\"channel\",\"event\":\"journal_cap_reached\"}\n";
    const uint64_t line_budget = kJournalFileCap - kCapMark.size();   // the marker always fits inside the cap
    for (auto& line : batch) {
        std::string l = line + "\n";
        if (!f) { ++dropped; ++errors; continue; }
        if (journal_capped_ || bytes + l.size() > line_budget) {
            if (!journal_capped_) {
                journal_capped_ = true;
                DWORD w = 0;
                if (bytes + kCapMark.size() <= kJournalFileCap &&
                    WriteFile(f, kCapMark.data(), static_cast<DWORD>(kCapMark.size()), &w, nullptr))
                    bytes += w;
            }
            ++dropped;
            continue;
        }
        DWORD w = 0;
        bool ok = WriteFile(f, l.data(), static_cast<DWORD>(l.size()), &w, nullptr) && w == l.size();
        bytes += w;
        if (ok) { ++written; ++unflushed_; } else { ++errors; ++dropped; }
    }
    uint64_t now = GetTickCount64();
    bool flushed = false;
    if (f && unflushed_ && (force || now - last_flush_ms_ >= 1000)) {
        flushed = FlushFileBuffers(f) != 0;
        if (!flushed) ++errors;
        unflushed_ = 0;
        last_flush_ms_ = now;
    }
    std::lock_guard<std::mutex> g(mu_);
    counters_.journal_lines += written;
    counters_.journal_dropped += dropped;
    counters_.journal_errors += errors;
    counters_.journal_bytes = bytes;
    if (flushed) ++counters_.journal_flushes;
}

// Waits for a cancelled operation's terminal completion. False = not observed within the
// bound: the operation may still own its OVERLAPPED and buffer.
bool LocalChannel::drain(Io&, void* ovp, bool& pending) {
    if (!pending) return true;
    auto* ov = static_cast<OVERLAPPED*>(ovp);
    HANDLE pipe = static_cast<HANDLE>(pipe_);
    CancelIoEx(pipe, ov);
    if (WaitForSingleObject(ov->hEvent, kDrainTimeoutMs) != WAIT_OBJECT_0) {
        std::lock_guard<std::mutex> g(mu_);
        ++counters_.undrained;
        return false;
    }
    DWORD n = 0;
    GetOverlappedResult(pipe, ov, &n, FALSE);   // usually ERROR_OPERATION_ABORTED; either way it is done
    pending = false;
    ResetEvent(ov->hEvent);
    return true;
}

bool LocalChannel::disconnect(Io& io) {
    // Publish first: from here push_out refuses, and nothing old can reach the next client.
    bool was_connected;
    {
        std::lock_guard<std::mutex> g(mu_);
        was_connected = connected_.load();
        connected_ = false;
        ++epoch_;
        out_.clear();
        in_.clear();
        if (was_connected) ++counters_.disconnects;
    }
    bool ok = drain(io, &io.conn, io.listening) && drain(io, &io.read, io.reading) && drain(io, &io.write, io.writing);
    if (!ok) return false;
    DisconnectNamedPipe(static_cast<HANDLE>(pipe_));
    io.partial.clear();
    io.discard_line = false;
    return true;
}

void LocalChannel::run() {
    Io& io = *io_;
    try {
        loop(io);
    } catch (...) {
        failed_ = true;   // exception boundary (finding 4): the worker stops, the process does not terminate
    }
    shutdown(io);
}

void LocalChannel::shutdown(Io& io) {
    bool drained = false;
    try {
        drained = disconnect(io);
        flush_journal(true);
    } catch (...) {
        drained = false;
    }
    if (!drained) {
        failed_ = true;
        (void)io_.release();   // still owned by the system: deliberately leaked with its events and the pipe
        return;
    }
    if (journal_file_) { CloseHandle(static_cast<HANDLE>(journal_file_)); journal_file_ = nullptr; }
    CloseHandle(io.conn.hEvent);
    CloseHandle(io.read.hEvent);
    CloseHandle(io.write.hEvent);
    CloseHandle(static_cast<HANDLE>(pipe_));
}

void LocalChannel::loop(Io& io) {
    HANDLE pipe = static_cast<HANDLE>(pipe_);
    HANDLE stop = static_cast<HANDLE>(stop_event_);
    HANDLE wake = static_cast<HANDLE>(wake_event_);
    auto connected_now = [&] {
        std::lock_guard<std::mutex> g(mu_);
        connected_ = true;
        ++epoch_;
        ++counters_.connects;
    };
    auto fail_stop = [&] { failed_ = true; };

    for (;;) {
        if (!connected_ && !io.listening) {
            ResetEvent(io.conn.hEvent);
            if (ConnectNamedPipe(pipe, &io.conn)) {
                connected_now();
            } else {
                DWORD e = GetLastError();
                if (e == ERROR_IO_PENDING) io.listening = true;
                else if (e == ERROR_PIPE_CONNECTED) connected_now();
                else {
                    DisconnectNamedPipe(pipe);   // e.g. ERROR_NO_DATA: a client came and went; reset the instance
                    if (WaitForSingleObject(stop, 100) == WAIT_OBJECT_0) return;
                    continue;
                }
            }
        }
        if (connected_ && drop_epoch_.exchange(0) == epoch_.load()) {
            note("client_dropped", "local_frame_rejected_by_core");
            if (!disconnect(io)) { fail_stop(); return; }
            continue;
        }
        if (connected_ && !io.reading) {
            ResetEvent(io.read.hEvent);
            DWORD n = 0;
            if (!ReadFile(pipe, io.rbuf, sizeof(io.rbuf), &n, &io.read) && GetLastError() != ERROR_IO_PENDING) {
                if (!disconnect(io)) { fail_stop(); return; }
                continue;
            }
            io.reading = true;   // a synchronous completion also signals the event; handled below
        }
        if (connected_ && !io.writing) {
            {
                std::lock_guard<std::mutex> g(mu_);
                if (!out_.empty()) { io.wframe = out_.front() + "\n"; out_.pop_front(); }
                else io.wframe.clear();
            }
            if (!io.wframe.empty()) {
                ResetEvent(io.write.hEvent);
                if (!WriteFile(pipe, io.wframe.data(), static_cast<DWORD>(io.wframe.size()), nullptr, &io.write) &&
                    GetLastError() != ERROR_IO_PENDING) {
                    if (!disconnect(io)) { fail_stop(); return; }
                    continue;
                }
                io.writing = true;
            }
        }
        // Only events of operations actually pending: a completed manual-reset event
        // left in the set would satisfy every wait and spin the worker.
        HANDLE waits[5] = {stop, wake};
        DWORD nwaits = 2;
        if (io.listening) waits[nwaits++] = io.conn.hEvent;
        if (io.reading) waits[nwaits++] = io.read.hEvent;
        if (io.writing) waits[nwaits++] = io.write.hEvent;
        DWORD r = WaitForMultipleObjects(nwaits, waits, FALSE, 250);
        if (r == WAIT_OBJECT_0) return;
        flush_journal(false);
        if (io.listening && WaitForSingleObject(io.conn.hEvent, 0) == WAIT_OBJECT_0) {
            DWORD dummy = 0;
            io.listening = false;
            ResetEvent(io.conn.hEvent);
            if (GetOverlappedResult(pipe, &io.conn, &dummy, FALSE)) connected_now();
            else DisconnectNamedPipe(pipe);
        }
        if (io.reading && WaitForSingleObject(io.read.hEvent, 0) == WAIT_OBJECT_0) {
            DWORD n = 0;
            io.reading = false;   // completed: no longer owned by the system
            ResetEvent(io.read.hEvent);
            if (!GetOverlappedResult(pipe, &io.read, &n, FALSE)) {
                if (!disconnect(io)) { fail_stop(); return; }
                continue;
            }
            const char* loss = nullptr;
            uint64_t ep = epoch_.load();
            for (DWORD i = 0; i < n && !loss; ++i) {
                char c = io.rbuf[i];
                if (c == '\n') {
                    std::lock_guard<std::mutex> g(mu_);
                    if (io.discard_line) { ++counters_.oversize; loss = "oversize_frame"; }
                    else if (in_.size() >= kInCap) { ++counters_.in_dropped; loss = "inbound_full"; }
                    else { in_.push_back(InFrame{ep, io.partial}); ++counters_.frames_in; }
                    io.partial.clear();
                    io.discard_line = false;
                } else if (!io.discard_line) {
                    if (io.partial.size() >= kMaxFrame) { io.discard_line = true; io.partial.clear(); }
                    else io.partial.push_back(c);
                }
            }
            if (loss) {   // a frame that may carry authority was lost: end this local connection
                note("channel_loss", loss);
                {
                    std::lock_guard<std::mutex> g(mu_);
                    ++counters_.loss_disconnects;
                }
                if (!disconnect(io)) { fail_stop(); return; }
                continue;
            }
        }
        if (io.writing && WaitForSingleObject(io.write.hEvent, 0) == WAIT_OBJECT_0) {
            DWORD n = 0;
            io.writing = false;
            ResetEvent(io.write.hEvent);
            if (!GetOverlappedResult(pipe, &io.write, &n, FALSE) || n != io.wframe.size()) {
                if (!disconnect(io)) { fail_stop(); return; }
                continue;
            }
            std::lock_guard<std::mutex> g(mu_);
            ++counters_.frames_out;
        }
    }
}

}  // namespace re2net::adapter
