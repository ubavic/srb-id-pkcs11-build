const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pkcs_error = @import("pkcs_error.zig");

const PkcsError = pkcs_error.PkcsError;

pub const Object = union(enum) {
    certificate: CertificateObject,
    private_key: PrivateKeyObject,
    PublicKeyObject: PrivateKeyObject,
};

pub const CertificateObject = struct {
    class: pkcs.CK_OBJECT_CLASS,
    handle: pkcs.CK_OBJECT_HANDLE,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []const u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    certificate_type: pkcs.CK_CERTIFICATE_TYPE,
    trusted: pkcs.CK_BBOOL,
    certificate_category: pkcs.CK_CERTIFICATE_CATEGORY,
    check_value: []const u8,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    public_key_info: []const u8,
    subject: []const u8,
    id: []const u8,
    issuer: []const u8,
    serial_number: []const u8,
    value: []const u8,
    url: []const u8,
    hash_of_subject_public_key: []const u8,
    name_hash_algorithm: pkcs.CK_MECHANISM_TYPE,

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.check_value);
        allocator.free(self.public_key_info);
        allocator.free(self.subject);
        allocator.free(self.id);
        allocator.free(self.issuer);
        allocator.free(self.serial_number);
        allocator.free(self.value);
        allocator.free(self.url);
        allocator.free(self.hash_of_subject_public_key);
    }
};

pub const PrivateKeyObject = struct {
    class: pkcs.CK_OBJECT_CLASS,
    handle: pkcs.CK_OBJECT_HANDLE,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []const u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    key_type: pkcs.CK_KEY_TYPE,
    id: []const u8,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    derive: pkcs.CK_BBOOL,
    local: pkcs.CK_BBOOL,
    key_gen_mechanism: pkcs.CK_MECHANISM_TYPE,
    allowed_mechanisms: []const pkcs.CK_MECHANISM_TYPE,
    subject: []const u8,
    sensitive: pkcs.CK_BBOOL,
    decrypt: pkcs.CK_BBOOL,
    sign: pkcs.CK_BBOOL,
    sign_recover: pkcs.CK_BBOOL,
    unwrap: pkcs.CK_BBOOL,
    extractable: pkcs.CK_BBOOL,
    always_sensitive: pkcs.CK_BBOOL,
    never_extractable: pkcs.CK_BBOOL,
    wrap_with_trusted: pkcs.CK_BBOOL,
    unwrap_template: []pkcs.CK_ATTRIBUTE,
    always_authenticate: []pkcs.CK_ATTRIBUTE,
    public_key_info: []const u8,

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.id);
        allocator.free(self.allowed_mechanisms);
        allocator.free(self.subject);
        allocator.free(self.unwrap_template);
        allocator.free(self.always_authenticate);
        allocator.free(self.public_key_info);
    }
};

pub const PublicKeyObject = struct {
    class: pkcs.CK_OBJECT_CLASS,
    handle: pkcs.CK_OBJECT_HANDLE,
    token: pkcs.CK_BBOOL,
    private: pkcs.CK_BBOOL,
    modifiable: pkcs.CK_BBOOL,
    label: []const u8,
    copyable: pkcs.CK_BBOOL,
    destroyable: pkcs.CK_BBOOL,
    key_type: pkcs.CK_KEY_TYPE,
    id: []const u8,
    start_date: pkcs.CK_DATE,
    end_date: pkcs.CK_DATE,
    derive: pkcs.CK_BBOOL,
    local: pkcs.CK_BBOOL,
    key_gen_mechanism: pkcs.CK_MECHANISM_TYPE,
    allowed_mechanisms: []const pkcs.CK_MECHANISM_TYPE,
    subject: []const u8,
    encrypt: pkcs.CK_BBOOL,
    verify: pkcs.CK_BBOOL,
    verify_recover: pkcs.CK_BBOOL,
    wrap: pkcs.CK_BBOOL,
    trusted: pkcs.CK_BBOOL,
    wrap_template: []pkcs.CK_ATTRIBUTE,
    public_key_info: []const u8,

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.label);
        allocator.free(self.id);
        allocator.free(self.allowed_mechanisms);
        allocator.free(self.subject);
        allocator.free(self.public_key_info);
    }
};

pub const Attribute = struct {
    attribute_type: pkcs.CK_ATTRIBUTE_TYPE,
    data: []const u8,

    pub fn deinit(self: *Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

pub fn parseAttributes(
    allocator: std.mem.Allocator,
    template: []pkcs.CK_ATTRIBUTE,
) PkcsError![]Attribute {
    const search_template = allocator.alloc(Attribute, template.len) catch
        return PkcsError.HostMemory;

    var errored = false;

    for (template, 0..) |attribute, i| {
        const parsed_attribute = parseAttribute(allocator, attribute) catch {
            errored = true;
            break;
        };

        search_template[i] = parsed_attribute;
    }

    if (!errored) {
        deinitSearchTemplate(allocator, search_template);
        return PkcsError.HostMemory;
    }

    return search_template;
}

pub fn parseAttribute(
    allocator: std.mem.Allocator,
    attribute: pkcs.CK_ATTRIBUTE,
) std.mem.Allocator.Error!Attribute {
    const data = try allocator.alloc(u8, attribute.ulValueLen);

    return Attribute{
        .attribute_type = attribute.type,
        .data = data,
    };
}

pub fn deinitSearchTemplate(allocator: std.mem.Allocator, search_template: []Attribute) void {
    // TODO: skip elements that are not allocated
    for (search_template) |*attr| {
        attr.deinit(allocator);
    }
}
