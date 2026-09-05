const std = @import("std");
const warn = std.debug.print;

pub fn hexdump(buf: []const u8) void {
    for (buf) |C| {
        warn("{x:0>2}", .{C});
    }
    warn("\n", .{});
}


pub fn dir_exists(io: std.Io, path: []const u8) bool {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return false;
    dir.close(io);
    return true;
}
