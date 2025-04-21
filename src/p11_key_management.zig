const pkcs = @cImport({
    @cInclude("pkcs.h");
});

// not supported in the original module
pub export fn wrapKey(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]pkcs.CK_BYTE,
    _: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

// not supported in the original module
pub export fn unwrapKey(
    _: pkcs.CK_SESSION_HANDLE,
    _: ?*pkcs.CK_MECHANISM,
    _: pkcs.CK_OBJECT_HANDLE,
    _: ?[*]const pkcs.CK_BYTE,
    _: pkcs.CK_ULONG,
    _: ?[*]pkcs.CK_ATTRIBUTE,
    _: pkcs.CK_ULONG,
    _: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}
