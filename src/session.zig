const std = @import("std");

const pkcs_error = @import("pkcs_error.zig");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pcsc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const reader = @import("reader.zig");

var next_session_id: pkcs.CK_SLOT_ID = 1;

pub var sessions: std.AutoHashMap(pkcs.CK_SESSION_HANDLE, Session) = undefined;

pub const Session = struct {
    id: pkcs.CK_SESSION_HANDLE,
    card_handle: pcsc.LPSCARDHANDLE,
    reader_id: pkcs.CK_SLOT_ID,
    logged_in: bool,

    pub fn login(self: *Session) !void {
        self.logged_in = true;
    }

    pub fn logout(self: *Session) void {
        self.logged_in = false;
    }

    pub fn slotId(self: *const Session) pkcs.CK_SLOT_ID {
        return self.reader_id;
    }
};

pub fn newSession(
    slot_id: pkcs.CK_SLOT_ID,
) pkcs_error.PkcsError!pkcs.CK_SESSION_HANDLE {
    if (!reader.reader_states.contains(slot_id)) {
        return pkcs.CKR_SLOT_ID_INVALID;
    }

    return 0;
}

pub fn closeSession(session_handle: pkcs.CK_SESSION_HANDLE) pkcs_error.PkcsError!void {
    _ = session_handle;
}
