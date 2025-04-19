const pkcs = @cImport({
    @cInclude("pkcs.h");
});

pub export fn getFunctionStatus(_: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_PARALLEL;
}

pub export fn cancelFunction(_: pkcs.CK_SESSION_HANDLE) pkcs.CK_RV {
    return pkcs.CKR_FUNCTION_NOT_PARALLEL;
}
