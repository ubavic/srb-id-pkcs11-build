const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pcsc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const version = @import("version.zig");
const state = @import("state.zig");
const reader = @import("reader.zig");
const session = @import("session.zig");

const p11_parallel = @import("p11_parallel.zig");
const p11_random = @import("p11_random.zig");
const p11_slot_and_token = @import("p11_slot_and_token.zig");
const p11_key_management = @import("p11_key_management.zig");
const p11_session = @import("p11_session.zig");

export fn initialize(_: pkcs.CK_VOID_PTR) pkcs.CK_RV {
    if (state.initialized) {
        return pkcs.CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    const rv = pcsc.SCardEstablishContext(pcsc.SCARD_SCOPE_SYSTEM, null, null, &state.smart_card_context_handle);
    if (rv != pcsc.SCARD_S_SUCCESS) {
        return pkcs.CKR_FUNCTION_FAILED;
    }

    reader.reader_states = std.AutoHashMap(pkcs.CK_SLOT_ID, reader.ReaderState).init(state.allocator);
    session.sessions = std.AutoHashMap(pkcs.CK_SLOT_ID, session.Session).init(state.allocator);

    state.initialized = true;
    return pkcs.CKR_OK;
}

export fn finalize(reserved: pkcs.CK_VOID_PTR) pkcs.CK_RV {
    if (reserved != null) {
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    const rv = pcsc.SCardReleaseContext(state.smart_card_context_handle);
    if (rv != pcsc.SCARD_S_SUCCESS) {
        return pkcs.CKR_FUNCTION_FAILED;
    }

    return pkcs.CKR_OK;
}

export fn getInfo(info: ?*pkcs.CK_INFO) pkcs.CK_RV {
    if (!state.initialized) {
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (info == null) {
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    info.?.cryptokiVersion.major = pkcs.CRYPTOKI_VERSION_MAJOR;
    info.?.cryptokiVersion.minor = pkcs.CRYPTOKI_VERSION_MINOR;
    info.?.flags = 0;
    info.?.libraryVersion.major = version.major;
    info.?.libraryVersion.minor = version.minor;

    @memset(&info.?.libraryDescription, 0);
    std.mem.copyForwards(u8, &info.?.libraryDescription, "Module for Serbian personal ID");

    @memset(&info.?.manufacturerID, 0);
    std.mem.copyForwards(u8, &info.?.manufacturerID, "Nikola Ubavic");

    return pkcs.CKR_OK;
}

var functionList = pkcs.CK_FUNCTION_LIST{
    .version = pkcs.CK_VERSION{ .major = 0x02, .minor = 0x40 },
    .C_Initialize = initialize,
    .C_Finalize = finalize,
    .C_GetInfo = getInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = p11_slot_and_token.getSlotList,
    .C_GetSlotInfo = p11_slot_and_token.getSlotInfo,
    .C_GetTokenInfo = p11_slot_and_token.getTokenInfo,
    .C_GetMechanismList = p11_slot_and_token.getMechanismList,
    .C_GetMechanismInfo = p11_slot_and_token.getMechanismInfo,
    .C_InitToken = p11_slot_and_token.initToken,
    .C_InitPIN = p11_slot_and_token.initPin,
    .C_SetPIN = p11_slot_and_token.setPin,
    .C_OpenSession = p11_session.openSession,
    .C_CloseSession = p11_session.closeSession,
    .C_CloseAllSessions = p11_session.closeAllSessions,
    .C_GetSessionInfo = p11_session.getSessionInfo,
    .C_GetOperationState = p11_session.getOperationState,
    .C_SetOperationState = p11_session.setOperationState,
    .C_Login = p11_session.login,
    .C_Logout = p11_session.logout,
    .C_CreateObject = null,
    .C_CopyObject = null,
    .C_DestroyObject = null,
    .C_GetObjectSize = null,
    .C_GetAttributeValue = null,
    .C_SetAttributeValue = null,
    .C_FindObjectsInit = null,
    .C_FindObjects = null,
    .C_FindObjectsFinal = null,
    .C_EncryptInit = null,
    .C_Encrypt = null,
    .C_EncryptUpdate = null,
    .C_EncryptFinal = null,
    .C_DecryptInit = null,
    .C_Decrypt = null,
    .C_DecryptUpdate = null,
    .C_DecryptFinal = null,
    .C_DigestInit = null,
    .C_Digest = null,
    .C_DigestUpdate = null,
    .C_DigestKey = null,
    .C_DigestFinal = null,
    .C_SignInit = null,
    .C_Sign = null,
    .C_SignUpdate = null,
    .C_SignFinal = null,
    .C_SignRecoverInit = null,
    .C_SignRecover = null,
    .C_VerifyInit = null,
    .C_Verify = null,
    .C_VerifyUpdate = null,
    .C_VerifyFinal = null,
    .C_VerifyRecoverInit = null,
    .C_VerifyRecover = null,
    .C_DigestEncryptUpdate = null,
    .C_DecryptDigestUpdate = null,
    .C_SignEncryptUpdate = null,
    .C_DecryptVerifyUpdate = null,
    .C_GenerateKey = null,
    .C_GenerateKeyPair = null,
    .C_WrapKey = p11_key_management.wrapKey,
    .C_UnwrapKey = p11_key_management.unwrapKey,
    .C_DeriveKey = null,
    .C_SeedRandom = p11_random.seedRandom,
    .C_GenerateRandom = p11_random.generateRandom,
    .C_GetFunctionStatus = p11_parallel.getFunctionStatus,
    .C_CancelFunction = p11_parallel.cancelFunction,
    .C_WaitForSlotEvent = null,
};

export fn C_GetFunctionList(function_list: ?*?*pkcs.CK_FUNCTION_LIST) pkcs.CK_RV {
    if (function_list == null) {
        return pkcs.CKR_ARGUMENTS_BAD;
    }

    function_list.?.* = &functionList;
    return pkcs.CKR_OK;
}
