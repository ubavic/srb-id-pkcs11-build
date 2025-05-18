const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn signInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn sign(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = data;
    _ = data_len;
    _ = signature;
    _ = signature_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn signUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = part;
    _ = part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn signFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = signature;
    _ = signature_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn signRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn signRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]pkcs.CK_BYTE,
    signature_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = data;
    _ = data_len;
    _ = signature;
    _ = signature_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verify(
    session_handle: pkcs.CK_SESSION_HANDLE,
    data: ?[*]const pkcs.CK_BYTE,
    data_len: pkcs.CK_ULONG,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = data;
    _ = data_len;
    _ = signature;
    _ = signature_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyUpdate(
    session_handle: pkcs.CK_SESSION_HANDLE,
    part: ?[*]const pkcs.CK_BYTE,
    part_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = part;
    _ = part_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = signature;
    _ = signature_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyRecoverInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    mechanism: ?*pkcs.CK_MECHANISM,
    key: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = mechanism;
    _ = key;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn verifyRecover(
    session_handle: pkcs.CK_SESSION_HANDLE,
    signature: ?[*]const pkcs.CK_BYTE,
    signature_len: pkcs.CK_ULONG,
    data: ?[*]pkcs.CK_BYTE,
    data_len: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
