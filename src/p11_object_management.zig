const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pkcs_error = @import("pkcs_error.zig");
const object = @import("object.zig");
const session = @import("session.zig");

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
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    new_object_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;
    _ = template;
    _ = count;
    _ = new_object_handle;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn destroyObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn getObjectSize(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    size: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;
    _ = size;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn getAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;
    _ = template;
    _ = count;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn setAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;
    _ = template;
    _ = count;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn findObjectsInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.None) catch |err|
        return pkcs_error.toRV(err);

    if (template == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    current_session.search_index = 0;

    const search_template = object.parseAttributes(current_session.allocator, template.?[0..count]) catch |err|
        return pkcs_error.toRV(err);

    current_session.findObjects(search_template) catch |err|
        return pkcs_error.toRV(err);

    current_session.operation = session.Operation.Search;

    return pkcs.CKR_OK;
}

pub export fn findObjects(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handles: ?[*]pkcs.CK_OBJECT_HANDLE,
    max_object_count: pkcs.CK_ULONG,
    object_count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.Search) catch |err|
        return pkcs_error.toRV(err);

    if (object_handles == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (object_count == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (current_session.found_objects == null)
        return pkcs.CKR_GENERAL_ERROR;

    if (current_session.found_objects.?.len < current_session.search_index) {
        object_count.?.* = 0;
        return pkcs.CKR_OK;
    }

    const remaining_objects: pkcs.CK_ULONG = current_session.found_objects.?.len - current_session.search_index;
    const objects_to_return = @min(remaining_objects, max_object_count);

    object_count.?.* = objects_to_return;

    std.mem.copyForwards(pkcs.CK_OBJECT_HANDLE, object_handles.?[0..max_object_count], current_session.found_objects.?[current_session.search_index .. current_session.search_index + objects_to_return]);

    current_session.search_index += objects_to_return;

    return pkcs.CKR_OK;
}

pub export fn findObjectsFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.Search) catch |err|
        return pkcs_error.toRV(err);

    current_session.operation = session.Operation.None;

    return pkcs.CKR_OK;
}
