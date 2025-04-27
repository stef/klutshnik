const std = @import("std");
const warn = std.debug.print;

pub fn hexdump(buf: []const u8) void {
    for (buf) |C| {
        warn("{x:0>2}", .{C});
    }
    warn("\n", .{});
}


pub fn dir_exists(path: []const u8) bool {
    var cwd = std.fs.cwd();
    const args: std.fs.Dir.OpenDirOptions = undefined;
    var dir = cwd.openDir(path, args) catch return false;
    dir.close();
    return true;
}
