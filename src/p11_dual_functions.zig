const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn digestEncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = part;
    _ = part_len;
    _ = encrypted_part;
    _ = encrypted_part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn decryptDigestUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = encrypted_part;
    _ = encrypted_part_len;
    _ = part;
    _ = part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn signEncryptUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
    encrypted_part: ?[*]pkcs.CK_BYTE,
    encrypted_part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = part;
    _ = part_len;
    _ = encrypted_part;
    _ = encrypted_part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn decryptVerifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    encrypted_part: ?[*]const pkcs.CK_BYTE,
    encrypted_part_len: pkcs.CK_ULONG,
    part: ?[*]pkcs.CK_BYTE,
    part_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = encrypted_part;
    _ = encrypted_part_len;
    _ = part;
    _ = part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
