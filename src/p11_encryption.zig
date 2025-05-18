const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn encryptInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn encrypt(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    encrypted_data: ?[*]pkcs.CK_BYTE,
    encrypted_data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = data;
    _ = data_len;
    _ = encrypted_data;
    _ = encrypted_data_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn encryptFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    last_encrypted_part: ?[*]pkcs.CK_BYTE,
    last_encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = last_encrypted_part;
    _ = last_encrypted_part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
