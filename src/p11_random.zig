const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");

// not supported in the original module
pub export fn seedRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    _: pkcs.CK_BYTE_PTR,
    _: pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (!session.sessions.contains(session_handle)) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    return pkcs.CKR_RANDOM_SEED_NOT_SUPPORTED;
}

pub export fn generateRandom(
    session_handle: pkcs.CK_SESSION_HANDLE,
    random_data: [*c]pkcs.CK_BYTE,
    random_size: pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.get(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (current_session.closed) {
        return pkcs.CKR_SESSION_CLOSED;
    }

    var i: c_ulong = 0;
    var remaining_size = random_size;
    while (i < random_size) {
        const segment_size: u8 = @min(128, remaining_size);

        const segment = current_session.card.readRandom(state.allocator, segment_size) catch |err|
            return pkcs_error.toRV(err);

        std.mem.copyForwards(u8, random_data[i .. i + segment_size], segment[0..segment_size]);

        i += segment_size;
        remaining_size -= segment_size;

        state.allocator.free(segment);
    }

    return pkcs.CKR_OK;
}
