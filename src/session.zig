const std = @import("std");

const PkcsError = @import("pkcs_error.zig").PkcsError;

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const sc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const hasher = @import("hasher.zig");
const state = @import("state.zig");
const reader = @import("reader.zig");
const smart_card = @import("smart-card.zig");

var next_session_id: pkcs.CK_SESSION_HANDLE = 1;

pub var sessions: std.AutoHashMap(pkcs.CK_SESSION_HANDLE, Session) = undefined;

pub const Session = struct {
    id: pkcs.CK_SESSION_HANDLE,
    card: smart_card.Card,
    reader_id: pkcs.CK_SLOT_ID,
    logged_in: bool = false,
    closed: bool = false,
    write_enabled: bool,
    digest_initialized: bool = false,
    multipart_digest: bool = false,
    hasher: hasher.Hasher = undefined,

    pub fn login(self: *Session) !void {
        self.logged_in = true;
    }

    pub fn logout(self: *Session) void {
        self.logged_in = false;
    }

    pub fn slot(self: *Session) void {
        return self.card.reader_id;
    }

    pub fn resetDigestSession(self: *Session, allocator: std.mem.Allocator) void {
        self.digest_initialized = false;
        self.multipart_digest = false;
        self.hasher.destroy(allocator);
    }
};

pub fn newSession(
    slot_id: pkcs.CK_SESSION_HANDLE,
    write_enabled: bool,
) PkcsError!pkcs.CK_SESSION_HANDLE {
    const session_id: pkcs.CK_SESSION_HANDLE = next_session_id;
    next_session_id += 1;

    const reader_entry = reader.reader_states.get(slot_id);
    if (reader_entry == null)
        return PkcsError.SlotIdInvalid;

    const reader_state = reader_entry.?;

    const card = try smart_card.connect(
        state.allocator,
        state.smart_card_context_handle,
        reader_state.name,
    );

    sessions.put(
        session_id,
        Session{
            .id = session_id,
            .card = card,
            .reader_id = slot_id,
            .write_enabled = write_enabled,
        },
    ) catch {
        return PkcsError.HostMemory;
    };

    return session_id;
}

pub fn closeSession(session_handle: pkcs.CK_SESSION_HANDLE) PkcsError!void {
    const session_entry = sessions.getPtr(session_handle);
    if (session_entry == null) {
        return PkcsError.SessionHandleInvalid;
    }

    const session = session_entry.?;

    if (session.closed) {
        return PkcsError.SessionClosed;
    }

    session.closed = true;

    session.hasher.destroy(state.allocator);

    _ = session.card.disconnect() catch {};

    _ = sessions.remove(session_handle);
}
