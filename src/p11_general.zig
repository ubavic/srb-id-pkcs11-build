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

const p11_decryption = @import("p11_decryption.zig");
const p11_digest = @import("p11_digest.zig");
const p11_dual_functions = @import("p11_dual_functions.zig");
const p11_encryption = @import("p11_encryption.zig");
const p11_key_management = @import("p11_key_management.zig");
const p11_object_management = @import("p11_object_management.zig");
const p11_parallel = @import("p11_parallel.zig");
const p11_random = @import("p11_random.zig");
const p11_session = @import("p11_session.zig");
const p11_sign = @import("p11_sign.zig");
const p11_slot_and_token = @import("p11_slot_and_token.zig");

export fn initialize(_: pkcs.CK_VOID_PTR) pkcs.CK_RV {
    if (state.initialized)
        return pkcs.CKR_CRYPTOKI_ALREADY_INITIALIZED;

    const rv = pcsc.SCardEstablishContext(pcsc.SCARD_SCOPE_SYSTEM, null, null, &state.smart_card_context_handle);
    if (rv != pcsc.SCARD_S_SUCCESS)
        return pkcs.CKR_FUNCTION_FAILED;

    reader.reader_states = std.AutoHashMap(pkcs.CK_SLOT_ID, reader.ReaderState).init(state.allocator);
    session.initSessions(state.allocator);

    state.initialized = true;
    return pkcs.CKR_OK;
}

export fn finalize(reserved: pkcs.CK_VOID_PTR) pkcs.CK_RV {
    if (reserved != null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    const rv = pcsc.SCardReleaseContext(state.smart_card_context_handle);
    if (rv != pcsc.SCARD_S_SUCCESS)
        return pkcs.CKR_FUNCTION_FAILED;

    return pkcs.CKR_OK;
}

export fn getInfo(info: ?*pkcs.CK_INFO) pkcs.CK_RV {
    if (!state.initialized)
        return pkcs.CKR_CRYPTOKI_NOT_INITIALIZED;

    if (info == null)
        return pkcs.CKR_ARGUMENTS_BAD;

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
    .C_Login = p11_session.sessionLogin,
    .C_Logout = p11_session.sessionLogout,
    .C_CreateObject = p11_object_management.createObject,
    .C_CopyObject = p11_object_management.copyObject,
    .C_DestroyObject = p11_object_management.destroyObject,
    .C_GetObjectSize = p11_object_management.getObjectSize,
    .C_GetAttributeValue = p11_object_management.getAttributeValue,
    .C_SetAttributeValue = p11_object_management.setAttributeValue,
    .C_FindObjectsInit = p11_object_management.findObjectsInit,
    .C_FindObjects = p11_object_management.findObjects,
    .C_FindObjectsFinal = p11_object_management.findObjectsFinal,
    .C_EncryptInit = p11_encryption.encryptInit,
    .C_Encrypt = p11_encryption.encrypt,
    .C_EncryptUpdate = p11_encryption.encrypt,
    .C_EncryptFinal = p11_encryption.encryptFinal,
    .C_DecryptInit = p11_decryption.decryptInit,
    .C_Decrypt = p11_decryption.decrypt,
    .C_DecryptUpdate = p11_decryption.decryptUpdate,
    .C_DecryptFinal = p11_decryption.decryptFinal,
    .C_DigestInit = p11_digest.digestInit,
    .C_Digest = p11_digest.digest,
    .C_DigestUpdate = p11_digest.digestUpdate,
    .C_DigestKey = p11_digest.digestKey,
    .C_DigestFinal = p11_digest.digestFinal,
    .C_SignInit = p11_sign.signInit,
    .C_Sign = p11_sign.sign,
    .C_SignUpdate = p11_sign.signUpdate,
    .C_SignFinal = p11_sign.signFinal,
    .C_SignRecoverInit = p11_sign.signRecoverInit,
    .C_SignRecover = p11_sign.signRecover,
    .C_VerifyInit = p11_sign.verifyInit,
    .C_Verify = p11_sign.verify,
    .C_VerifyUpdate = p11_sign.verifyUpdate,
    .C_VerifyFinal = p11_sign.verifyFinal,
    .C_VerifyRecoverInit = p11_sign.verifyRecoverInit,
    .C_VerifyRecover = p11_sign.verifyRecover,
    .C_DigestEncryptUpdate = p11_dual_functions.digestEncryptUpdate,
    .C_DecryptDigestUpdate = p11_dual_functions.decryptDigestUpdate,
    .C_SignEncryptUpdate = p11_dual_functions.signEncryptUpdate,
    .C_DecryptVerifyUpdate = p11_dual_functions.decryptVerifyUpdate,
    .C_GenerateKey = p11_key_management.generateKey,
    .C_GenerateKeyPair = p11_key_management.generateKeyPair,
    .C_WrapKey = p11_key_management.wrapKey,
    .C_UnwrapKey = p11_key_management.unwrapKey,
    .C_DeriveKey = p11_key_management.deriveKey,
    .C_SeedRandom = p11_random.seedRandom,
    .C_GenerateRandom = p11_random.generateRandom,
    .C_GetFunctionStatus = p11_parallel.getFunctionStatus,
    .C_CancelFunction = p11_parallel.cancelFunction,
    .C_WaitForSlotEvent = p11_slot_and_token.waitForSlotEvent,
};

export fn C_GetFunctionList(function_list: ?*?*pkcs.CK_FUNCTION_LIST) pkcs.CK_RV {
    if (function_list == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    function_list.?.* = &functionList;
    return pkcs.CKR_OK;
}
