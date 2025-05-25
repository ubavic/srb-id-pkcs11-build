const std = @import("std");

const PkcsError = @import("pkcs_error.zig").PkcsError;

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const sc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

const apdu = @import("apdu.zig");

pub const Card = struct {
    card_handle: sc.SCARDHANDLE,
    active_card_protocol: sc.DWORD,

    fn selectFile(
        self: *const Card,
        allocator: std.mem.Allocator,
        name: []const u8,
        selection_method: u8,
        selection_option: u8,
        ne: u32,
    ) PkcsError!void {
        const data_unit = apdu.build(
            allocator,
            0x00,
            0xA4,
            selection_method,
            selection_option,
            name,
            ne,
        ) catch {
            return PkcsError.HostMemory;
        };
        defer allocator.free(data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);

        if (!responseOK(response)) {
            return PkcsError.DeviceError;
        }
    }

    fn transmit(
        self: *const Card,
        allocator: std.mem.Allocator,
        data_unit: []u8,
    ) PkcsError![]u8 {
        var buf: [256 + 2]u8 = undefined;
        var buf_len: sc.DWORD = buf.len;

        const rv = sc.SCardTransmit(
            self.card_handle,
            @ptrCast(&self.active_card_protocol),
            data_unit.ptr,
            data_unit.len,
            null,
            &buf,
            &buf_len,
        );

        try scToPkcsError(rv);

        const out = allocator.alloc(u8, buf_len) catch
            return PkcsError.HostMemory;

        std.mem.copyForwards(u8, out, buf[0..buf_len]);

        return out;
    }

    fn readFile(
        self: *Card,
        allocator: std.mem.Allocator,
        file_name: []u8,
    ) PkcsError![]u8 {
        _ = self;
        _ = allocator;
        _ = file_name;
    }

    pub fn disconnect(
        self: *Card,
    ) PkcsError!void {
        const rv = sc.SCardDisconnect(self.card_handle, sc.SCARD_LEAVE_CARD);
        try scToPkcsError(rv);
    }

    pub fn initCrypto(
        self: *const Card,
        allocator: std.mem.Allocator,
    ) PkcsError!void {
        const file_name = [_]u8{ 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };
        try self.selectFile(allocator, &file_name, 0x04, 0x00, 0);
    }

    pub fn readRandom(
        self: *const Card,
        allocator: std.mem.Allocator,
        length: u8,
    ) PkcsError![]u8 {
        const data_unit = apdu.build(allocator, 0xB0, 0x83, 0x00, 0x00, null, length) catch
            return PkcsError.HostMemory;

        defer allocator.free(data_unit);

        const response = try self.transmit(allocator, data_unit);

        if (!responseOK(response)) {
            defer allocator.free(response);
            return PkcsError.DeviceError;
        }

        return response;
    }

    pub fn verifyPin(self: *const Card, allocator: std.mem.Allocator, pin: []const u8) PkcsError!bool {
        if (true) {
            return true;
        }

        //TODO: Implement pin pad and error codes

        const data_unit = apdu.build(allocator, 0x00, 0x20, 0x00, 0x80, pin, 0) catch
            return PkcsError.HostMemory;
        defer allocator.free(data_unit);

        const response = try self.transmit(allocator, data_unit);
        defer allocator.free(response);

        if (!responseOK(response)) {
            return false;
        }

        return true;
    }
};

pub fn connect(
    allocator: std.mem.Allocator,
    smart_card_context_handle: sc.SCARDHANDLE,
    reader_name: []const u8,
) PkcsError!Card {
    var card_handle: sc.SCARDHANDLE = 0;
    var active_protocol: sc.DWORD = 0;

    const rv = sc.SCardConnect(
        smart_card_context_handle,
        reader_name.ptr,
        sc.SCARD_SHARE_SHARED,
        sc.SCARD_PROTOCOL_T0 | sc.SCARD_PROTOCOL_T1,
        &card_handle,
        &active_protocol,
    );

    try scToPkcsError(rv);

    const card = Card{
        .card_handle = card_handle,
        .active_card_protocol = active_protocol,
    };

    try card.initCrypto(allocator);

    return card;
}

fn responseIs(rsp: []const u8, expected: [2]u8) bool {
    if (rsp.len < 2) return false;
    const sw1 = rsp[rsp.len - 2];
    const sw2 = rsp[rsp.len - 1];
    return sw1 == expected[0] and sw2 == expected[1];
}

fn responseOK(rsp: []const u8) bool {
    return responseIs(rsp, [_]u8{ 0x90, 0x00 });
}

fn scToPkcsError(err: sc.LONG) PkcsError!void {
    return switch (err) {
        sc.SCARD_S_SUCCESS => {},
        sc.SCARD_E_NO_SMARTCARD => PkcsError.TokenNoPresent,
        else => PkcsError.DeviceError,
    };
}
