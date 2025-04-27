const std = @import("std");
const Allocator = std.mem.Allocator;
const sodium = @cImport({
    @cInclude("sodium.h");
});


pub fn SecretAllocator() type {
    return struct {
        parent_allocator: Allocator,

        const Self = @This();

        pub fn init(parent_allocator: Allocator) Self {
            return Self{
                .parent_allocator = parent_allocator,
            };
        }

        pub fn allocator(self: *Self) Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }

        fn alloc(
            ctx: *anyopaque,
            len: usize,
            log2_ptr_align: u8,
            ra: usize,
        ) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const result = self.parent_allocator.rawAlloc(len, log2_ptr_align, ra);
            if (result) |buf| {
                if(len > 0 and 0!=sodium.sodium_mlock(@ptrCast(buf),len)) {
                    self.parent_allocator.rawFree(buf[0..len], log2_ptr_align, ra);
                    return null;
                }
            }
            return result;
        }

        fn resize(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            new_len: usize,
            ra: usize,
        ) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if(new_len==0) _=sodium.sodium_munlock(@ptrCast(buf),buf.len);
            if (self.parent_allocator.rawResize(buf, log2_buf_align, new_len, ra)) {
                if(new_len>buf.len) _=sodium.sodium_mlock(buf.ptr, new_len);
                return true;
            }
            std.debug.assert(new_len > buf.len);
            return false;
        }

        fn free(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            ra: usize,
        ) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            _ = sodium.sodium_munlock(buf.ptr,buf.len);
            self.parent_allocator.rawFree(buf, log2_buf_align, ra);
        }
    };
}

pub fn secretAllocator(
    parent_allocator: Allocator,
) SecretAllocator() {
    return SecretAllocator().init(parent_allocator);
}

test "SecretAllocator" {
    var allocator_buf: [10]u8 = undefined;
    var fixedBufferAllocator = std.mem.validationWrap(std.heap.FixedBufferAllocator.init(&allocator_buf));
    var allocator_state = secretAllocator(fixedBufferAllocator.allocator());
    const allocator = allocator_state.allocator();

    var a = try allocator.alloc(u8, 10);
    try std.testing.expect(allocator.resize(a, 5));
    a = a[0..5];
    try std.testing.expect(!allocator.resize(a, 20));
    allocator.free(a);
}
