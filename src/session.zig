const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const sc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const object = @import("object.zig");
const hasher = @import("hasher.zig");
const pkcs_error = @import("pkcs_error.zig");
const reader = @import("reader.zig");
const smart_card = @import("smart-card.zig");
const state = @import("state.zig");

const PkcsError = pkcs_error.PkcsError;

var next_session_id: pkcs.CK_SESSION_HANDLE = 1;

var sessions: std.AutoHashMap(pkcs.CK_SESSION_HANDLE, Session) = undefined;

pub const Operation = enum {
    None,
    Digest,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    Search,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    id: pkcs.CK_SESSION_HANDLE,
    card: smart_card.Card,
    reader_id: pkcs.CK_SLOT_ID,
    closed: bool = false,
    write_enabled: bool,
    operation: Operation = Operation.None,
    multipart_operation: bool = false,
    key: pkcs.CK_OBJECT_HANDLE = 0,
    hasher: hasher.Hasher = undefined,
    pin: [8]u8 = undefined,
    objects: []object.Object,
    search_index: usize = 0,
    found_objects: ?[]pkcs.CK_OBJECT_HANDLE = null,

    pub fn login(self: *Session, new_pin: []const u8) PkcsError!void {
        errdefer reader.setUserType(self.reader_id, reader.UserType.None);
        const verified = try self.card.verifyPin(self.allocator, new_pin);
        const user_status = if (verified) reader.UserType.User else reader.UserType.None;
        reader.setUserType(self.reader_id, user_status);
    }

    pub fn logout(self: *Session) void {
        reader.setUserType(self.reader_id, reader.UserType.None);
    }

    pub fn loggedIn(self: *Session) bool {
        return reader.getUserType(self.reader_id) != reader.UserType.None;
    }

    pub fn assertNoOperation(self: *Session) PkcsError!void {
        if (self.operation != Operation.None)
            return PkcsError.OperationActive;
    }

    pub fn assertOperation(self: *Session, operation: Operation) PkcsError!void {
        if (self.operation != operation) {
            return if (self.operation == Operation.None)
                PkcsError.OperationNotInitialized
            else
                PkcsError.OperationActive;
        }
    }

    pub fn slot(self: *Session) void {
        return self.card.reader_id;
    }

    pub fn resetSignSession(self: *Session) void {
        self.key = 0;
        self.resetDigestSession();
    }

    pub fn resetDigestSession(self: *Session) void {
        self.multipart_operation = false;
        self.hasher.destroy(self.allocator);
        self.operation = Operation.None;
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
    ) std.mem.Allocator.Error![]u8 {
        _ = self;
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

    pub fn findObjects(
        self: *Session,
        attributes: []object.Attribute,
    ) PkcsError!void {
        _ = self;
        _ = attributes;
    }
};

pub fn initSessions(allocator: std.mem.Allocator) void {
    sessions = std.AutoHashMap(pkcs.CK_SLOT_ID, Session).init(allocator);
}

pub fn newSession(
    allocator: std.mem.Allocator,
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
        allocator,
        state.smart_card_context_handle,
        reader_state.name,
    );

    // TODO: Load and parse certificates
    const objects: []object.Object = allocator.alloc(object.Object, 0) catch
        return PkcsError.HostMemory;

    sessions.put(
        session_id,
        Session{
            .id = session_id,
            .card = card,
            .reader_id = slot_id,
            .write_enabled = write_enabled,
            .allocator = allocator,
            .objects = objects,
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

    if (login_required and !current_session.loggedIn())
        return PkcsError.UserNotLoggedIn;

    return current_session;
}

pub fn closeSession(session_handle: pkcs.CK_SESSION_HANDLE) PkcsError!void {
    const session_entry = sessions.getPtr(session_handle);
    if (session_entry == null) {
        return PkcsError.SessionHandleInvalid;
    }

    const current_session = session_entry.?;

    if (current_session.closed)
        return PkcsError.SessionClosed;

    current_session.closed = true;

    current_session.hasher.destroy(current_session.allocator);

    _ = current_session.card.disconnect() catch {};

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
