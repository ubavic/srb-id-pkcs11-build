const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const sc = @cImport({
    @cInclude("pcsclite.h");
    @cInclude("winscard.h");
    @cInclude("wintypes.h");
});

var next_reader_id: pkcs.CK_SLOT_ID = 1;

pub var reader_states: std.AutoHashMap(pkcs.CK_SLOT_ID, ReaderState) = undefined;

pub const ReaderState = struct {
    name: []const u8,
    active: bool,
    card_present: bool,
    recognized: bool,

    pub fn refreshCardPresent(self: *ReaderState, smart_card_context_handle: sc.SCARDHANDLE) pkcs.CK_RV {
        var card_handle: sc.SCARDHANDLE = 0;
        var active_protocol: sc.DWORD = 0;

        const r = sc.SCardConnect(
            smart_card_context_handle,
            self.name.ptr,
            sc.SCARD_SHARE_SHARED,
            sc.SCARD_PROTOCOL_T0 | sc.SCARD_PROTOCOL_T1,
            &card_handle,
            &active_protocol,
        );

        switch (r) {
            sc.SCARD_S_SUCCESS => {
                self.card_present = true;
                _ = sc.SCardDisconnect(card_handle, sc.SCARD_LEAVE_CARD);
            },
            sc.SCARD_E_NO_SMARTCARD => {
                self.card_present = false;
            },
            sc.SCARD_W_UNPOWERED_CARD, sc.SCARD_W_UNRESPONSIVE_CARD, sc.SCARD_E_READER_UNAVAILABLE => return pkcs.CKR_DEVICE_ERROR,
            else => return pkcs.CKR_GENERAL_ERROR,
        }

        return pkcs.CKR_OK;
    }

    pub fn writeShortName(self: *const ReaderState, output: []u8) void {
        const open_index = std.mem.indexOfScalar(u8, self.name, '[');
        const close_index = std.mem.indexOfScalar(u8, self.name, ']');

        if (open_index == null or close_index == null or close_index.? <= open_index.?) {
            const len = @min(self.name.len, output.len);
            @memcpy(output[0..len], self.name[0..len]);
            if (len < output.len) output[len] = 0;
            return;
        }

        const before = self.name[0..open_index.?];
        const after = self.name[(close_index.? + 1)..];

        const trimmed_before = std.mem.trimRight(u8, before, " ");
        const trimmed_after = std.mem.trimLeft(u8, after, " ");

        var idx: usize = 0;

        if (idx + trimmed_before.len <= output.len) {
            @memcpy(output[idx..][0..trimmed_before.len], trimmed_before);
            idx += trimmed_before.len;
        }

        if (trimmed_after.len > 0 and idx < output.len) {
            output[idx] = ' ';
            idx += 1;
        }

        if (idx + trimmed_after.len <= output.len) {
            @memcpy(output[idx..][0..trimmed_after.len], trimmed_after);
            idx += trimmed_after.len;
        }

        if (idx < output.len) output[idx] = 0;
    }
};

pub fn refreshStatuses(allocator: std.mem.Allocator, smart_card_context_handle: sc.SCARDHANDLE) pkcs.CK_RV {
    var readers_multi_string: [*c]u8 = null;
    var readers: sc.DWORD = sc.SCARD_AUTOALLOCATE;

    const rv1 = sc.SCardListReaders(
        smart_card_context_handle,
        null,
        @ptrCast(&readers_multi_string),
        &readers,
    );

    if (rv1 != sc.SCARD_S_SUCCESS and rv1 != sc.SCARD_E_NO_READERS_AVAILABLE) {
        if (rv1 == sc.SCARD_E_NO_MEMORY)
            return pkcs.CKR_HOST_MEMORY;

        return pkcs.CKR_GENERAL_ERROR;
    }

    defer _ = sc.SCardFreeMemory(smart_card_context_handle, readers_multi_string);

    resetStates();

    if (rv1 != sc.SCARD_E_NO_READERS_AVAILABLE) {
        const reader_names = parseMultiString(allocator, readers_multi_string) catch {
            return pkcs.CKR_GENERAL_ERROR;
        };

        for (reader_names) |reader_name| {
            addIfNotExists(allocator, reader_name) catch {
                return pkcs.CKR_GENERAL_ERROR;
            };
        }
    }

    var reader_iterator = reader_states.iterator();
    while (reader_iterator.next()) |reader_state_entry| {
        if (!reader_state_entry.value_ptr.active)
            continue;

        const rv = reader_state_entry.value_ptr.*.refreshCardPresent(smart_card_context_handle);
        if (rv != pkcs.CKR_OK) {
            return rv;
        }
    }

    return pkcs.CKR_OK;
}

pub fn addIfNotExists(allocator: std.mem.Allocator, reader_name: [*:0]const u8) !void {
    const reader_name_slice = std.mem.sliceTo(reader_name, 0);

    var iter = reader_states.iterator();
    while (iter.next()) |entry| {
        if (std.mem.eql(u8, entry.value_ptr.name, reader_name_slice)) {
            entry.value_ptr.*.active = true;
            return;
        }
    }

    const allocated_name = try allocator.allocSentinel(u8, reader_name_slice.len, 0);

    std.mem.copyForwards(u8, allocated_name, reader_name_slice);
    try reader_states.put(
        next_reader_id,
        ReaderState{
            .name = allocated_name,
            .active = true,
            .card_present = false,
            .recognized = true, // TODO
        },
    );

    next_reader_id += 1;
}

fn resetStates() void {
    var it = reader_states.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.*.active = false;
        entry.value_ptr.*.card_present = false;
    }
}

fn parseMultiString(allocator: std.mem.Allocator, input: [*:0]const u8) ![][:0]const u8 {
    var list = std.ArrayList([:0]const u8).init(allocator);
    errdefer list.deinit();

    var i: usize = 0;
    while (true) {
        const start = input + i;
        const len = std.mem.len(start);

        if (len == 0)
            break;

        const slice = input[i .. i + len :0];
        try list.append(slice);

        i += len + 1;
    }

    return try list.toOwnedSlice();
}
