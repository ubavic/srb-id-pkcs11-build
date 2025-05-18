const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn createObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    object_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = template;
    _ = count;
    _ = object_handle;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn copyObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    new_object_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object;
    _ = template;
    _ = count;
    _ = new_object_handle;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn destroyObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn getObjectSize(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object: pkcs.CK_OBJECT_HANDLE,
    size: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object;
    _ = size;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn getAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object;
    _ = template;
    _ = count;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn setAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object;
    _ = template;
    _ = count;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn findObjectsInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = template;
    _ = count;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn findObjects(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handles: ?[*]pkcs.CK_OBJECT_HANDLE,
    max_object_count: pkcs.CK_ULONG,
    object_count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handles;
    _ = max_object_count;
    _ = object_count;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn findObjectsFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
