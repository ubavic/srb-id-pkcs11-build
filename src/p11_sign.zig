const pkcs_error = @import("pkcs_error.zig");
const state = @import("state.zig");
const session = @import("session.zig");
const hasher = @import("hasher.zig");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn signInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    if (mechanism == null) {
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const current_session = session_entry.?;

    if (current_session.sign_initialized) {
        return pkcs.CKR_OPERATION_ACTIVE;
    }

    var hash_mechanism: hasher.HasherType = undefined;
    var use_hasher = false;
    switch (mechanism.?.*.mechanism) {
        pkcs.CKM_MD5_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.md5;
            use_hasher = true;
        },
        pkcs.CKM_SHA1_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha1;
            use_hasher = true;
        },
        pkcs.CKM_SHA256_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha256;
            use_hasher = true;
        },
        pkcs.CKM_SHA384_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha384;
            use_hasher = true;
        },
        pkcs.CKM_SHA512_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha512;
            use_hasher = true;
        },
        pkcs.CKM_RSA_PKCS,
        pkcs.CKM_RSA_X_509,
        => {
            // TODO: Implement these algorithms
            use_hasher = false;
            return pkcs.CKR_MECHANISM_INVALID;
        },
        else => {
            return pkcs.CKR_MECHANISM_INVALID;
        },
    }

    if (use_hasher) {
        current_session.digest_initialized = true;
        current_session.hasher = hasher.createAndInit(hash_mechanism, state.allocator) catch
            return pkcs.CKR_HOST_MEMORY;
    }

    current_session.key = key; // TODO: validate key handle
    current_session.sign_initialized = true;

    return pkcs.CKR_OK;
}

pub export fn sign(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (!current_session.sign_initialized) {
        return pkcs.CKR_OPERATION_NOT_INITIALIZED;
    }

    if (current_session.multipart_operation) {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (signature_len == null) {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    const required_signature_size = current_session.signatureSize();
    if (signature == null) {
        signature_len.?.* = required_signature_size;
        return pkcs.CKR_OK;
    }

    if (data == null) {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (signature_len.?.* < required_signature_size) {
        return pkcs.CKR_BUFFER_TOO_SMALL;
    }

    const casted_data: [*]u8 = @ptrCast(data);
    current_session.signUpdate(casted_data[0..data_len]);
    const computed_signature = current_session.signFinalize(state.allocator) catch {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_HOST_MEMORY;
    };

    const signature_casted: [*]u8 = @ptrCast(signature);

    @memcpy(signature_casted, computed_signature);
    state.allocator.free(computed_signature);

    current_session.resetSignSession(state.allocator);

    return pkcs.CKR_OK;
}

pub export fn signUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (!current_session.sign_initialized) {
        return pkcs.CKR_OPERATION_NOT_INITIALIZED;
    }

    if (part == null) {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    current_session.multipart_operation = true;

    const casted_part: [*]u8 = @ptrCast(part);
    current_session.signUpdate(casted_part[0..part_len]);

    return pkcs.CKR_OK;
}

pub export fn signFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (!current_session.sign_initialized) {
        return pkcs.CKR_OPERATION_NOT_INITIALIZED;
    }

    const required_signature_size = current_session.signatureSize();
    if (signature == null) {
        signature_len.?.* = required_signature_size;
        return pkcs.CKR_OK;
    }

    if (signature_len.?.* < required_signature_size) {
        return pkcs.CKR_BUFFER_TOO_SMALL;
    }

    const computed_signature = current_session.signFinalize(state.allocator) catch {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_HOST_MEMORY;
    };

    const signature_casted: [*]u8 = @ptrCast(signature);

    @memcpy(signature_casted, computed_signature);
    state.allocator.free(computed_signature);

    current_session.resetSignSession(state.allocator);
    return pkcs.CKR_OK;
}

pub export fn signRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    _ = mechanism;
    _ = key;
    return pkcs.CKR_KEY_TYPE_INCONSISTENT;
}

pub export fn signRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    _ = data;
    _ = data_len;
    _ = signature;
    _ = signature_len;

    return pkcs.CKR_OPERATION_NOT_INITIALIZED;
}

pub export fn verifyInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (mechanism == null) {
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (current_session.verify_initialized) {
        return pkcs.CKR_OPERATION_ACTIVE;
    }

    var hash_mechanism: hasher.HasherType = undefined;
    var use_hasher = false;
    switch (mechanism.?.*.mechanism) {
        pkcs.CKM_MD5_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.md5;
            use_hasher = true;
        },
        pkcs.CKM_SHA1_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha1;
            use_hasher = true;
        },
        pkcs.CKM_SHA256_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha256;
            use_hasher = true;
        },
        pkcs.CKM_SHA384_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha384;
            use_hasher = true;
        },
        pkcs.CKM_SHA512_RSA_PKCS => {
            hash_mechanism = hasher.HasherType.sha512;
            use_hasher = true;
        },
        pkcs.CKM_RSA_PKCS,
        pkcs.CKM_RSA_X_509,
        => {
            // TODO: Implement these algorithms
            use_hasher = false;
            return pkcs.CKR_MECHANISM_INVALID;
        },
        else => {
            return pkcs.CKR_MECHANISM_INVALID;
        },
    }

    if (use_hasher) {
        current_session.digest_initialized = true;
        current_session.hasher = hasher.createAndInit(hash_mechanism, state.allocator) catch
            return pkcs.CKR_HOST_MEMORY;
    }

    current_session.key = key;
    current_session.verify_initialized = true;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verify(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (!current_session.verify_initialized) {
        return pkcs.CKR_OPERATION_NOT_INITIALIZED;
    }

    if (current_session.multipart_operation) {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_FUNCTION_CANCELED;
    }

    if (signature_len == null) {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    //TODO: Implementation

    _ = data;
    _ = data_len;
    _ = signature;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (!current_session.verify_initialized) {
        return pkcs.CKR_OPERATION_NOT_INITIALIZED;
    }

    if (part == null) {
        current_session.resetSignSession(state.allocator);
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    //TODO: Implementation

    _ = part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    const current_session = session_entry.?;

    if (!current_session.verify_initialized) {
        return pkcs.CKR_OPERATION_NOT_INITIALIZED;
    }

    //TODO: Implementation

    _ = signature;
    _ = signature_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    _ = mechanism;
    _ = key;
    return pkcs.CKR_KEY_TYPE_INCONSISTENT;
}

pub export fn verifyRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const session_entry = session.sessions.getPtr(session_handle);
    if (session_entry == null) {
        return pkcs.CKR_SESSION_HANDLE_INVALID;
    }

    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;
    return pkcs.CKR_OPERATION_NOT_INITIALIZED;
}
