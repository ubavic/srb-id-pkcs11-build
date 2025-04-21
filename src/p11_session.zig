const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pcsc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const reader = @import("reader.zig");
const session = @import("session.zig");

pub export fn openSession(
    slot_id: pkcs.CK_SLOT_ID,
    flags: pkcs.CK_FLAGS,
    application: ?*anyopaque,
    notify: pkcs.CK_NOTIFY,
    session_handle: ?*pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    _ = application;
    _ = notify;

    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if ((flags & pkcs.CKF_SERIAL_SESSION) == 0) {
        return pkcs.CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    if (session_handle == null) {
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const write_enabled = (flags & pkcs.CKF_RW_SESSION) != 0;

    session_handle.?.* = session.newSession(slot_id, write_enabled) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_OK;
}

pub export fn closeSession(session_handle: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    session.closeSession(session_handle) catch |err|
        return pkcs_error.toRV(err);

    return pkcs.CKR_OK;
}

pub export fn closeAllSessions(slot_id: pkcs.CK_SLOT_ID) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!reader.reader_states.contains(slot_id)) {
        return pkcs.CKR_SLOT_ID_INVALID;
    }

    var err: pkcs.CK_RV = pkcs.CKR_OK;
    var it = session.sessions.iterator();
    while (it.next()) |entry| {
        const sessionId = entry.key_ptr.*;
        const session_entry = entry.value_ptr.*;
        if (session_entry.reader_id == slot_id) {
            session.closeSession(sessionId) catch |e| {
                err = pkcs_error.toRV(e);
            };
        }
    }

    return err;
}

pub export fn getSessionInfo(
    session_handle: pkcs.CK_SESSION_HANDLE,
    session_info: ?*pkcs.CK_SESSION_INFO,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (session_info == null) {
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const session_entry = session.sessions.get(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (current_session.closed) {
        return pkcs.CKR_SESSION_CLOSED;
    }

    session_info.?.slotID = current_session.reader_id;
    session_info.?.flags = pkcs.CKF_SERIAL_SESSION | (if (current_session.write_enabled) pkcs.CKF_RW_SESSION else 0);

    return pkcs.CKR_OK;
}

// not supported in the original module
pub export fn getOperationState(
    session_handle: pkcs.CK_SESSION_HANDLE,
    operationS_state: ?[*]pkcs.CK_BYTE,
    operation_state_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = operationS_state;
    _ = operation_state_len;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

// not supported in the original module
pub export fn setOperationState(
    session_handle: pkcs.CK_SESSION_HANDLE,
    operation_state: ?[*]const pkcs.CK_BYTE,
    operation_state_len: pkcs.CK_ULONG,
    encryption_key: pkcs.CK_OBJECT_HANDLE,
    authentication_key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = operation_state;
    _ = operation_state_len;
    _ = encryption_key;
    _ = authentication_key;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn login(
    session_handle: pkcs.CK_SESSION_HANDLE,
    user_type: pkcs.CK_USER_TYPE,
    pin: ?[*]const pkcs.CK_UTF8CHAR,
    pin_length: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = user_type;
    _ = pin;
    _ = pin_length;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn logout(session_handle: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    _ = session_handle;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
