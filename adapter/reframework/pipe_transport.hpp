// LocalChannel: the plugin side of the contract's local channel (CONTRACT.md §2).
// One named-pipe server instance, current-user-only DACL, remote clients rejected.
// The worker thread ONLY moves bytes between the pipe and bounded queues and appends
// journal lines to a file; it never calls the engine or the REFramework SDK.
//
// Local connection identity (pipe review 1328 finding 1): every client connection has
// its own epoch. Inbound frames carry the epoch they arrived under; an outbound frame is
// accepted only for the exact current connected epoch. A disconnect is published
// (connected=false, epoch advanced) BEFORE the queues are cleared, so no old frame can be
// queued for the next client.
//
// Loss (finding 6): an inbound frame that cannot be delivered (queue full, oversize
// line) is never silently dropped: the worker journals it and disconnects the client, so
// the plugin sees a new epoch and the companion must reconnect and send a fresh session.
//
// Overlapped lifetime (finding 2): all overlapped state lives in one heap block owned by
// the worker. A cancelled operation is waited for until its terminal completion before
// that state is reused or freed; if a completion cannot be observed within a bound, the
// block and its handles are deliberately leaked and the worker stops (failed()).
#pragma once
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace re2net::adapter {

struct ChannelCounters {
    uint64_t frames_in = 0, frames_out = 0, in_dropped = 0, out_refused = 0, oversize = 0, loss_disconnects = 0;
    uint64_t journal_lines = 0, journal_dropped = 0, journal_errors = 0, journal_bytes = 0, journal_flushes = 0;
    uint64_t connects = 0, disconnects = 0, undrained = 0;
};

struct InFrame {
    uint64_t epoch = 0;   // the local connection this frame arrived under
    std::string line;
};

class LocalChannel {
public:
    static constexpr size_t kInCap = 64, kOutCap = 128, kJournalCap = 1024, kMaxFrame = 1024;
    static constexpr size_t kMaxJournalLine = 1024;                 // bytes per journal line
    static constexpr uint64_t kJournalFileCap = 8ull * 1024 * 1024; // bytes per process journal file
    static constexpr size_t kJournalBatch = 64;                     // lines per worker iteration
    static constexpr unsigned kDrainTimeoutMs = 5000;

    LocalChannel();
    // Only reached when no worker was started (initialize failure) or at orderly teardown;
    // the plugin never destroys a channel whose worker may be running.
    ~LocalChannel();
    // All throwing allocation happens before the worker starts. Returns false (or throws)
    // only while no worker thread exists.
    bool start(const std::wstring& pipe_name, const std::wstring& journal_path, std::string& why);
    void request_stop();                       // signal only; never joins from a loader callback

    // Game thread side.
    bool push_out(const std::string& frame, uint64_t epoch);   // false = refused (full, oversize, not that live connection)
    bool push_journal(const std::string& line);
    std::vector<InFrame> take_in();
    void drop_client(uint64_t epoch);          // force a reconnect of that connection (e.g. undecodable local frame)
    bool connected() const { return connected_.load(); }
    uint64_t connection_epoch() const { return epoch_.load(); }   // advances on every connect and disconnect
    bool failed() const { return failed_.load(); }               // worker stopped: no further local I/O
    ChannelCounters counters();

private:
    struct Io;
    void run();
    void loop(Io& io);
    bool disconnect(Io& io);                   // false = an operation could not be drained
    bool drain(Io& io, void* ov, bool& pending);
    void shutdown(Io& io);
    bool create_instance();
    void flush_journal(bool force);
    void note(const char* event, const std::string& detail);   // worker-originated journal line

    std::wstring pipe_name_, journal_path_;
    void* pipe_ = nullptr;          // HANDLE
    void* stop_event_ = nullptr;    // HANDLE
    void* wake_event_ = nullptr;    // HANDLE (outbound/journal/drop work)
    void* journal_file_ = nullptr;  // HANDLE, worker only
    bool journal_capped_ = false;
    uint64_t last_flush_ms_ = 0, unflushed_ = 0;
    std::unique_ptr<Io> io_;
    std::thread worker_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> failed_{false};
    std::atomic<uint64_t> epoch_{0};
    std::atomic<uint64_t> drop_epoch_{0};
    std::mutex mu_;
    std::deque<InFrame> in_;
    std::deque<std::string> out_, journal_;
    ChannelCounters counters_{};
};

}  // namespace re2net::adapter
