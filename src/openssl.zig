const std = @import("std");

const openssl = @cImport({
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/decoder.h");
});

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const object = @import("object.zig");
const pkcs_error = @import("pkcs_error.zig");
const PkcsError = pkcs_error.PkcsError;

pub fn init() void {
    _ = openssl.OPENSSL_init_crypto(openssl.OPENSSL_INIT_ADD_ALL_CIPHERS | openssl.OPENSSL_INIT_ADD_ALL_DIGESTS, null);
}

pub fn freeX509(
    x509: *openssl.struct_x509_st,
) void {
    openssl.X509_free(x509);
}

pub fn parseX509(
    data: []const u8,
) PkcsError!*openssl.struct_x509_st {
    var a: [*c]const u8 = @ptrCast(data.ptr);

    const x509 = openssl.d2i_X509(null, &a, @intCast(data.len));
    if (x509 == null)
        return PkcsError.GeneralError;

    return x509.?;
}

pub fn loadObjects(
    allocator: std.mem.Allocator,
    x509: *openssl.struct_x509_st,
    certificate_handle: pkcs.CK_OBJECT_HANDLE,
    private_key_handle: pkcs.CK_OBJECT_HANDLE,
    public_key_handle: pkcs.CK_OBJECT_HANDLE,
) PkcsError![3]object.Object {
    var buf: [1024]u8 = std.mem.zeroes([1024]u8);

    const subj_name = openssl.X509_get_subject_name(x509);
    const subj_ptr = openssl.X509_NAME_oneline(subj_name, @ptrCast(&buf), buf.len - 1);
    const subject = try allocateString(allocator, &buf, subj_ptr);
    errdefer allocator.free(subject);

    const issuer_name = openssl.X509_get_issuer_name(x509);
    const issuer_ptr = openssl.X509_NAME_oneline(issuer_name, @ptrCast(&buf), buf.len - 1);
    const issuer = try allocateString(allocator, &buf, issuer_ptr);
    errdefer allocator.free(subject);

    const certificate_url = try allocEmptySlice(allocator);

    const certificate_object: object.CertificateObject = object.CertificateObject{
        .handle = certificate_handle,
        .class = pkcs.CKO_CERTIFICATE,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_FALSE,
        .modifiable = pkcs.CK_FALSE,
        .label = undefined,
        .copyable = pkcs.CK_FALSE,
        .destroyable = pkcs.CK_FALSE,
        .certificate_type = pkcs.CKC_X_509,
        .trusted = pkcs.CK_FALSE,
        .certificate_category = pkcs.CK_CERTIFICATE_CATEGORY_TOKEN_USER,
        .check_value = undefined,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .public_key_info = undefined,
        .subject = subject,
        .id = undefined,
        .issuer = issuer,
        .serial_number = undefined,
        .value = undefined,
        .url = certificate_url,
        .hash_of_subject_public_key = undefined,
        .name_hash_algorithm = undefined,
    };

    const private_key_label = try allocEmptySlice(allocator);
    const private_key_subject = try allocEmptySlice(allocator);

    const private_key_object: object.PrivateKeyObject = object.PrivateKeyObject{
        .handle = private_key_handle,
        .class = pkcs.CKO_PRIVATE_KEY,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_TRUE,
        .modifiable = pkcs.CK_FALSE,
        .label = private_key_label,
        .copyable = pkcs.CK_FALSE,
        .destroyable = pkcs.CK_FALSE,
        .key_type = undefined,
        .id = undefined,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .derive = pkcs.CK_FALSE,
        .local = pkcs.CK_TRUE,
        .key_gen_mechanism = undefined,
        .allowed_mechanisms = undefined,
        .subject = private_key_subject,
        .sensitive = undefined,
        .decrypt = pkcs.CK_TRUE,
        .sign = pkcs.CK_TRUE,
        .sign_recover = undefined,
        .unwrap = undefined,
        .extractable = pkcs.CK_FALSE,
        .always_sensitive = pkcs.CK_TRUE,
        .never_extractable = pkcs.CK_TRUE,
        .wrap_with_trusted = undefined,
        .unwrap_template = undefined,
        .always_authenticate = undefined,
        .public_key_info = undefined,
    };

    const public_key_label = try allocEmptySlice(allocator);
    const public_key_subject = try allocEmptySlice(allocator);

    const public_key_object: object.PublicKeyObject = object.PublicKeyObject{
        .handle = public_key_handle,
        .class = pkcs.CKO_PUBLIC_KEY,
        .token = pkcs.CK_TRUE,
        .private = pkcs.CK_FALSE,
        .modifiable = undefined,
        .label = public_key_label,
        .copyable = undefined,
        .destroyable = undefined,
        .key_type = undefined,
        .id = undefined,
        .start_date = pkcs.CK_DATE{},
        .end_date = pkcs.CK_DATE{},
        .derive = pkcs.CK_FALSE,
        .local = pkcs.CK_TRUE,
        .key_gen_mechanism = undefined,
        .allowed_mechanisms = undefined,
        .subject = public_key_subject,
        .encrypt = if (public_key_handle == 0x80000008) pkcs.CK_TRUE else pkcs.CK_FALSE,
        .verify = pkcs.CK_TRUE,
        .verify_recover = pkcs.CK_FALSE,
        .wrap = pkcs.CK_FALSE,
        .trusted = pkcs.CK_FALSE,
        .wrap_template = undefined,
        .public_key_info = undefined,
    };

    const object2 = object.Object{ .private_key = private_key_object };
    const object1 = object.Object{ .certificate = certificate_object };
    const object3 = object.Object{ .public_key = public_key_object };

    return [3]object.Object{ object1, object2, object3 };
}

fn allocateString(
    allocator: std.mem.Allocator,
    buffer: *[1024]u8,
    str_ptr: [*c]u8,
) PkcsError![]u8 {
    if (str_ptr == null)
        return PkcsError.GeneralError;

    const result: []u8 = buffer[0..std.mem.len(str_ptr)];

    const result_copy = allocator.allocSentinel(u8, result.len, 0) catch
        return PkcsError.HostMemory;

    std.mem.copyForwards(u8, result_copy, result);

    return result_copy;
}

fn allocEmptySlice(
    allocator: std.mem.Allocator,
) PkcsError![]u8 {
    return allocator.alloc(u8, 0) catch
        return PkcsError.HostMemory;
}
