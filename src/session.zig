const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const sc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const hasher = @import("hasher.zig");
const pkcs_error = @import("pkcs_error.zig");
const reader = @import("reader.zig");
const smart_card = @import("smart-card.zig");
const state = @import("state.zig");

const PkcsError = pkcs_error.PkcsError;

var next_session_id: pkcs.CK_SESSION_HANDLE = 1;

var sessions: std.AutoHashMap(pkcs.CK_SESSION_HANDLE, Session) = undefined;

pub const Session = struct {
    id: pkcs.CK_SESSION_HANDLE,
    card: smart_card.Card,
    reader_id: pkcs.CK_SLOT_ID,
    logged_in: bool = false,
    closed: bool = false,
    write_enabled: bool,
    sign_initialized: bool = false,
    verify_initialized: bool = false,
    digest_initialized: bool = false,
    multipart_operation: bool = false,
    key: pkcs.CK_OBJECT_HANDLE = 0,
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

    pub fn resetSignSession(self: *Session, allocator: std.mem.Allocator) void {
        self.key = 0;
        self.resetDigestSession(allocator);
    }

    pub fn resetDigestSession(self: *Session, allocator: std.mem.Allocator) void {
        self.digest_initialized = false;
        self.multipart_operation = false;
        self.hasher.destroy(allocator);
    }

    pub fn signatureSize(self: *Session) usize {
        _ = self;
        unreachable;
    }

    pub fn signUpdate(self: *Session, data: []const u8) void {
        _ = self;
        _ = data;
        unreachable;
    }

    pub fn signFinalize(
        self: *Session,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        _ = self;
        _ = allocator;
        unreachable;
    }

    pub fn verifyUpdate(self: *Session, data: []const u8) void {
        _ = self;
        _ = data;
        unreachable;
    }

    pub fn verifyFinalize(
        self: *Session,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        _ = self;
        _ = allocator;
        unreachable;
    }
};

pub fn initSessions(allocator: std.mem.Allocator) void {
    sessions = std.AutoHashMap(pkcs.CK_SLOT_ID, Session).init(allocator);
}

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

pub fn getSession(
    session_handle: pkcs.CK_SESSION_HANDLE,
    login_required: bool,
) PkcsError!*Session {
    if (!state.initialized)
        return PkcsError.CryptokiNotInitialized;

    const session_entry = sessions.getPtr(session_handle);
    if (session_entry == null)
        return PkcsError.SessionHandleInvalid;

    const current_session = session_entry.?;

    if (login_required and !current_session.logged_in)
        return PkcsError.UserNotLoggedIn;

    return current_session;
}

pub fn closeSession(session_handle: pkcs.CK_SESSION_HANDLE) PkcsError!void {
    const session_entry = sessions.getPtr(session_handle);
    if (session_entry == null) {
        return PkcsError.SessionHandleInvalid;
    }

    const session = session_entry.?;

    if (session.closed)
        return PkcsError.SessionClosed;

    session.closed = true;

    session.hasher.destroy(state.allocator);

    _ = session.card.disconnect() catch {};

    _ = sessions.remove(session_handle);
}

pub fn closeAllSessions(slot_id: pkcs.CK_SLOT_ID) pkcs.CK_RV {
    var err: pkcs.CK_RV = pkcs.CKR_OK;
    var it = sessions.iterator();

    while (it.next()) |entry| {
        const sessionId = entry.key_ptr.*;
        const session_entry = entry.value_ptr.*;
        if (session_entry.reader_id == slot_id) {
            closeSession(sessionId) catch |e| {
                err = pkcs_error.toRV(e);
            };
        }
    }

    return err;
}
