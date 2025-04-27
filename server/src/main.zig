const std = @import("std");
const builtin = @import("builtin");
const toml = @import("toml");
const ssl = @import("bearssl");
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const BufSet = std.BufSet;
const blake2b = std.crypto.hash.blake2.Blake2b256;
const ed25519 = std.crypto.sign.Ed25519;
const secret_allocator = @import("secret_allocator.zig");
const utils = @import("utils.zig");

pub const sodium = @cImport({
    @cInclude("sodium.h");
});
pub const toprf = @cImport({
    @cInclude("oprf/toprf.h");
});
pub const stp_dkg = @cImport({
    @cInclude("oprf/stp-dkg.h");
});
pub const tupdate = @cImport({
    @cInclude("oprf/toprf-update.h");
});
pub const oprf_utils = @cImport({
    @cInclude("oprf/utils.h");
});
pub const workaround = @cImport({
    @cInclude("./src/workaround.h");
});
pub const stdio = @cImport({
    @cInclude("stdio.h");
});

const DEBUG = (builtin.mode == std.builtin.OptimizeMode.Debug);
const warn = std.debug.print;

/// allocator
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

var s_state = secret_allocator.secretAllocator(allocator);
const s_allocator = s_state.allocator();

/// stdout
const stdout_file = std.io.getStdOut().writer();
var bw = std.io.bufferedWriter(stdout_file);
const stdout = bw.writer();

const sslStream = ssl.Stream(*net.Stream, *net.Stream);

const KeyStore = std.hash_map.AutoHashMap([sodium.crypto_generichash_BYTES]u8, Pubkeys);

var conn: net.Server.Connection = undefined;

const KlutshnikOp = enum(u8) {
    /// KMS ops
    CREATE  = 0,
    UPDATE  = 0x33,
    DECRYPT = 0x66,
    DELETE  = 0xff,

    /// authorization administration ops
    MODAUTH = 0xaa,

    _,
};

const KlutshnikPerms = enum(u8) {
    OWNER   = 1,
    DECRYPT = 2,
    UPDATE  = 4,
    DELETE  = 8,
    _,
};

const KeyType = enum(u8) {
    LTSig,
    Noise,
    _,
};

const CreateReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    msg0: [stp_dkg.stpvssdkg_start_msg_SIZE]u8 align(1),
};

const UpdateReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    msg0: [tupdate.toprfupdate_stp_start_msg_SIZE]u8 align(1),
    pk: [sodium.crypto_sign_PUBLICKEYBYTES]u8 align(1),
};

const DecryptReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    alpha: [sodium.crypto_core_ristretto255_BYTES]u8 align(1),
    verifier: [sodium.crypto_core_ristretto255_BYTES]u8 align(1),
    pk: [sodium.crypto_sign_PUBLICKEYBYTES]u8 align(1),
};

const DeleteReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    pk: [sodium.crypto_sign_PUBLICKEYBYTES]u8 align(1),
};

const ModAuthReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    readonly: u8 align(1),
};

const Pubkeys = struct {
    sigkey: [sodium.crypto_sign_PUBLICKEYBYTES]u8,
    noisekey: [sodium.crypto_scalarmult_BYTES]u8
};

const Config = struct {
    verbose: bool,
    /// the ip address the server is listening on
    address: []const u8,
    port: u16,
    /// tcp connection timeouts
    timeout: u16,
    /// the root directory where all data is stored
    datadir: [:0]const u8,
    /// how many processes can run in parallel
    max_kids: u16,
    /// server key in PEM format
    ssl_key: [:0]const u8,
    /// server cert in PEM format
    ssl_cert: [:0]const u8,
    /// maximum age still considered fresh, in seconds
    ts_epsilon: u64,
    /// server long-term signature key
    ltsigkey: [:0]const u8,
    /// server long-term noise key
    noisekey: [:0]const u8,
    /// salt for hashing record ids
    record_salt: []const u8,
    /// contents of authorized_keys file
    authorized_keys: KeyStore,
};

fn log(comptime msg: []const u8, args: anytype, recid: []const u8) void {
    const pid = std.os.linux.getpid();
    warn("{} {} {x:0>64} ", .{ pid, conn.address, std.fmt.fmtSliceHexLower(recid) });
    warn(msg, args);
}

fn sigHandler(sig: i32) callconv(.C) void {
    if (sig == std.posix.SIG.PIPE) {
        std.c._exit(9);
    }
}

fn setSigHandler() void {
    var sa: std.posix.Sigaction = .{
        .handler = .{ .handler = sigHandler },
        .mask = std.posix.empty_sigset,
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(std.posix.SIG.PIPE, &sa, null) catch |err| {
        log("failed to install sighandler: {}\n", .{err}, "");
        posix.exit(99);
    };
}

fn expandpath(path: []const u8) [:0]u8 {
    if (path[0] != '~') {
        return allocator.dupeZ(u8, path) catch @panic("OOM");
    }
    const home = posix.getenv("HOME") orelse "/nonexistant";
    const xpath = mem.concat(allocator, u8, &[_][]const u8{ home, path }) catch @panic("OOM");
    const xpathZ = allocator.dupeZ(u8, xpath) catch @panic("OOM");
    allocator.free(xpath);
    return xpathZ;
}

fn check_or_init(path: [:0]const u8, ktype: KeyType) void {
    std.fs.cwd().access(path, .{}) catch {
        const type_name = switch (ktype) {
            KeyType.LTSig => "signature",
            KeyType.Noise => "noise",
            else => @panic("invalid key type"),
        };

        // , sksize: const usize, pksize: const usize, name: []const u8
        if (std.os.argv.len == 2 and std.mem.eql(u8, std.mem.span(std.os.argv[1]), "init")) {
            const sksize = switch(ktype) {
                KeyType.LTSig => sodium.crypto_sign_SECRETKEYBYTES,
                KeyType.Noise => sodium.crypto_scalarmult_SCALARBYTES,
                else => @panic("invalid key type"),
            };
            const pksize = switch(ktype) {
                KeyType.LTSig => sodium.crypto_sign_PUBLICKEYBYTES,
                KeyType.Noise => sodium.crypto_scalarmult_BYTES,
                else => @panic("invalid key type"),
            };

            // create lt sig key pair
            const sk = s_allocator.alloc(u8, sksize) catch @panic("OOM");
            defer s_allocator.free(sk);
            const pk = allocator.alloc(u8, pksize) catch @panic("OOM");
            defer allocator.free(pk);
            switch(ktype) {
                KeyType.LTSig => {
                    if(0!=sodium.crypto_sign_keypair(pk.ptr, sk.ptr)) {
                        warn("failed to generate ltsigkey\n", .{});
                        posix.exit(1);
                    }
                },
                KeyType.Noise => {
                    sodium.randombytes_buf(sk.ptr, sodium.crypto_scalarmult_SCALARBYTES);
                    if(0!=sodium.crypto_scalarmult_base( pk.ptr, sk.ptr)) {
                        warn("failed to generated noise pubkey\n", .{});
                        posix.exit(1);
                    }
                },
                else => @panic("invalid key type"),
            }

            if (posix.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600)) |f| {
                defer posix.close(f);
                const w = posix.write(f, sk) catch |err| {
                    warn("failed to write lt {s} key: {}\n", .{type_name,err});
                    posix.exit(1);
                };
                if (w != sk.len) {
                    warn("failed to write secret key, disk full?\n", .{});
                    posix.exit(1);
                }
            } else |err| {
                warn("failed to save lt {s} key: {}\n", .{type_name,err});
                posix.exit(1);
            }

            const pubpath = mem.concat(allocator, u8, &[_][]const u8{ path, ".pub" }) catch @panic("OOM");
            defer allocator.free(pubpath);
            if (posix.open(pubpath, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o666)) |f| {
                defer posix.close(f);
                const w = posix.write(f, pk) catch |err| {
                    warn("failed to write lt {s} key: {}\n", .{type_name,err});
                    posix.exit(1);
                };
                if (w != pk.len) {
                    warn("failed to write public key, disk full?\n", .{});
                    posix.exit(1);
                }
            } else |err| {
                warn("failed to save lt {s} key: {}\n", .{type_name,err});
                posix.exit(1);
            }
            warn("successfully created long-term {s} key pair at:\n", .{type_name});
            warn("{s}\n", .{path});
            warn("and the public key - which you should make available to all clients -, is at:\n", .{});
            warn("{s}.pub\n", .{path});

            const b64pk: []u8 = allocator.alloc(u8, std.base64.standard.Encoder.calcSize(pk[0..].len)) catch @panic("OOM");
            defer allocator.free(b64pk);
            _ = std.base64.standard.Encoder.encode(b64pk, pk);
            warn("The following is the base64 encoded public key that you can also share:\n{s}\n", .{b64pk});
        } else {
            warn("Long-term {s} key at {s} is not readable.\n", .{type_name, path});
            warn("You can generate one by running: {s} init\n", .{std.mem.span(std.os.argv[0])});
            posix.exit(1);
        }
    };
}

fn load_pubkeys(path: []const u8) !KeyStore {
    var map = KeyStore.init(allocator);

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    // Wrap the file reader in a buffered reader.
    // Since it's usually faster to read a bunch of bytes at once.
    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();

    var line = std.ArrayList(u8).init(allocator);
    defer line.deinit();

    var k = [_]u8{0} ** sodium.crypto_generichash_BYTES;

    const writer = line.writer();
    while (reader.streamUntilDelimiter(writer, '\n', null)) {
        // Clear the line so we can reuse it.
        defer line.clearRetainingCapacity();
        var buf: [64]u8 = undefined;
        try std.base64.standard.Decoder.decode(buf[0..], line.items);
        const v = allocator.alloc(Pubkeys,1) catch @panic("oom");
        @memcpy(&v[0].sigkey, buf[0..32]);
        @memcpy(&v[0].noisekey, buf[32..]);
        blake2b.hash(v[0].sigkey[0..], &k, .{});
        try map.put(k, v[0]);
    } else |err| switch (err) {
        error.EndOfStream => { // end of file
            if (line.items.len > 0) {
                defer line.clearRetainingCapacity();
                var buf : [64]u8 = undefined;
                try std.base64.standard.Decoder.decode(buf[0..], line.items);
                const v = allocator.alloc(Pubkeys,1) catch @panic("oom");
                @memcpy(&v[0].sigkey, buf[0..32]);
                @memcpy(&v[0].noisekey, buf[32..]);
                blake2b.hash(v[0].sigkey[0..], &k, .{});
                try map.put(k, v[0]);
            }
        },
        else => return err, // Propagate error
    }
    return map;
}

fn ssl_file_missing(path: []const u8) noreturn {
    warn("The SSL key at {s} is not a readable file. Make sure this is a proper ssl key.\n", .{path});
    // todo
    //warn("Our GettingStarted document gives simple example of how to do so.\n", .{});
    //warn("Check out https://sphinx.pm/server_install.html .\n", .{});
    warn("Aborting.\n", .{});
    posix.exit(1);
}

fn loadcfg() anyerror!Config {
    @setCold(true);

    const home = posix.getenv("HOME") orelse "/nonexistant";
    const cfg1 = mem.concat(allocator, u8, &[_][]const u8{ home, "/.config/klutshnik/config" }) catch unreachable;
    defer allocator.free(cfg1);
    const cfg2 = mem.concat(allocator, u8, &[_][]const u8{ home, "/.klutshnikrc" }) catch unreachable;
    defer allocator.free(cfg2);

    const paths = [_][]const u8{
        "/etc/klutshnik/config",
        cfg1,
        cfg2,
        "klutshnik.cfg",
    };

    // default values for the Config structure
    var cfg = Config{
        .verbose = true,
        .address = "127.0.0.1",
        .port = 443,
        .timeout = 3,
        .datadir = "/var/lib/klutshnik",
        .max_kids = 5,
        .ssl_key = "server.pem",
        .ssl_cert = "certs.pem",
        .ts_epsilon = 600,
        .ltsigkey = "ltsig.key",
        .noisekey = "noise.key",
        .record_salt = undefined,
        .authorized_keys = undefined,
    };

    for (paths) |filename| {
        if (toml.parseFile(allocator, filename)) |p| {
            var parser: toml.Parser = p;
            defer parser.deinit();
            const t = parser.parse();
            if (t) |table| {
                defer table.deinit();

                if (table.keys.get("server")) |server| {
                    cfg.verbose = if (server.Table.keys.get("verbose")) |v| v.Boolean else cfg.verbose;
                    cfg.address = if (server.Table.keys.get("address")) |v| try allocator.dupe(u8, v.String) else cfg.address;
                    cfg.port = if (server.Table.keys.get("port")) |v| @intCast(v.Integer) else cfg.port;
                    cfg.timeout = if (server.Table.keys.get("timeout")) |v| @intCast(v.Integer) else cfg.timeout;
                    cfg.datadir = if (server.Table.keys.get("datadir")) |v| expandpath(v.String) else cfg.datadir;
                    cfg.max_kids = if (server.Table.keys.get("max_kids")) |v| @intCast(v.Integer) else cfg.max_kids;
                    cfg.ssl_key = if (server.Table.keys.get("ssl_key")) |v| expandpath(v.String) else cfg.ssl_key;
                    cfg.ssl_cert = if (server.Table.keys.get("ssl_cert")) |v| expandpath(v.String) else cfg.ssl_cert;
                    cfg.ts_epsilon = if (server.Table.keys.get("ts_epsilon")) |v| @intCast(v.Integer) else cfg.ts_epsilon;
                    cfg.ltsigkey = if (server.Table.keys.get("ltsigkey")) |v| expandpath(v.String) else cfg.ltsigkey;
                    cfg.noisekey = if (server.Table.keys.get("noisekey")) |v| expandpath(v.String) else cfg.noisekey;
                    if (server.Table.keys.get("authorized_keys")) |v| {
                        const path = expandpath(v.String);
                        cfg.authorized_keys = load_pubkeys(path) catch |err| {
                            warn("failed to load authorized keys from {s}: {}\n", .{path, err});
                            posix.exit(1);
                        };
                    } else {
                        warn("missing authorized_keys in configuration\nabort.", .{});
                        posix.exit(1);
                    }
                    if (server.Table.keys.get("record_salt")) |v| {
                        cfg.record_salt = allocator.dupe(u8, v.String) catch @panic("oom");
                    } else {
                        warn("missing record_salt in configuration\nabort.", .{});
                        posix.exit(1);
                    }
                }
            } else |err| {
                if (err == error.FileNotFound) continue;
                warn("error loading config {s}: {}\n", .{ filename, err });
            }
        } else |err| {
            if (err == error.FileNotFound) continue;
            warn("error loading config {s}: {}\n", .{ filename, err });
            return err;
        }
    }

    var env = try std.process.getEnvMap(allocator);
    defer env.deinit();
    cfg.verbose = std.mem.eql(u8, env.get("KLUTSHNIK_VERBOSE") orelse if(cfg.verbose) "true" else "false", "true");
    cfg.address     = if (env.get("KLUTSHNIK_ADDRESS"))     |v| try allocator.dupe(u8, v) else cfg.address;
    cfg.port        = if (env.get("KLUTSHNIK_PORT"))        |v| try std.fmt.parseInt(u16, v, 10) else cfg.port;
    cfg.timeout     = if (env.get("KLUTSHNIK_TIMEOUT"))     |v| try std.fmt.parseInt(u16, v, 10) else cfg.timeout;
    cfg.datadir     = if (env.get("KLUTSHNIK_DATADIR"))     |v| expandpath(v) else cfg.datadir;
    cfg.max_kids    = if (env.get("KLUTSHNIK_MAX_KIDS"))    |v| try std.fmt.parseInt(u16, v, 10) else cfg.max_kids;
    cfg.ssl_key     = if (env.get("KLUTSHNIK_SSL_KEY"))     |v| expandpath(v) else cfg.ssl_key;
    cfg.ssl_cert    = if (env.get("KLUTSHNIK_SSL_CERT"))    |v| expandpath(v) else cfg.ssl_cert;
    cfg.ts_epsilon  = if (env.get("KLUTSHNIK_TS_EPSILON"))  |v| try std.fmt.parseInt(u64, v, 10) else cfg.ts_epsilon;
    cfg.ltsigkey    = if (env.get("KLUTSHNIK_LTSIGKEY"))    |v| expandpath(v) else cfg.ltsigkey;
    cfg.noisekey    = if (env.get("KLUTSHNIK_NOISEKEY"))    |v| expandpath(v) else cfg.noisekey;
    cfg.record_salt = if (env.get("KLUTSHNIK_RECORD_SALT")) |v| try allocator.dupe(u8, v) else cfg.record_salt;

    std.fs.cwd().access(cfg.ssl_key, .{}) catch {
        ssl_file_missing(cfg.ssl_key);
    };
    std.fs.cwd().access(cfg.ssl_cert, .{}) catch {
        ssl_file_missing(cfg.ssl_cert);
    };

    if (cfg.verbose) {
        warn("cfg.address: {s}\n", .{cfg.address});
        warn("cfg.port: {}\n", .{cfg.port});
        warn("cfg.datadir: {s}\n", .{cfg.datadir});
        warn("cfg.ssl_key: {s}\n", .{cfg.ssl_key});
        warn("cfg.ssl_cert: {s}\n", .{cfg.ssl_cert});
        warn("cfg.ts_epsilon: {}\n", .{cfg.ts_epsilon});
        warn("cfg.verbose: {}\n", .{cfg.verbose});
        warn("cfg.ltsigkey: {s}\n", .{cfg.ltsigkey});
        warn("cfg.noisekey: {s}\n", .{cfg.noisekey});
        warn("cfg.record_salt: \"{s}\"\n", .{cfg.record_salt});
    }

    check_or_init(cfg.ltsigkey, KeyType.LTSig);
    check_or_init(cfg.noisekey, KeyType.Noise);
    if (std.os.argv.len == 2 and std.mem.eql(u8, std.mem.span(std.os.argv[1]), "init")) {
        posix.exit(0);
    }

    return cfg;
}

/// whenever anything fails during the execution of the protocol the server sends
/// "\x00\x04fail" to the client and terminates.
fn fail(s: *sslStream) noreturn {
    @setCold(true);
    if (DEBUG) {
        std.debug.dumpCurrentStackTrace(@frameAddress());
        warn("fail\n", .{});
        std.debug.dumpCurrentStackTrace(@returnAddress());
    }
    _ = s.write("\x00\x04fail") catch null;
    _ = s.flush() catch null;
    _ = std.os.linux.shutdown(conn.stream.handle, std.os.linux.SHUT.RDWR);
    _ = s.close() catch null;
    posix.exit(0);
}

fn read_pkt(s: *sslStream) []u8 {
    var lenbuf: [2]u8 = undefined;
    _ = s.read(lenbuf[0..]) catch |err| {
        handle_read_err(err, s);
    };
    const pktlen = std.mem.readInt(u16, lenbuf[0..2], std.builtin.Endian.big);
    //if(DEBUG) warn("read_pkt {}B\n", .{pktlen});
    var buf: []u8 = allocator.alloc(u8, pktlen) catch @panic("OOM");
    var i: usize = 0;
    while (i < buf.len) {
        //if(DEBUG) warn("read_pkt left {}B\n", .{i});
        if (s.read(buf[i..])) |r| {
            if (r == 0) break;
            i += r;
        } else |err| {
            handle_read_err(err, s);
        }
    }
    if (i < buf.len) {
        @panic("socket closed");
    }
    //if(DEBUG) warn("pkt ",.{}); utils.hexdump(buf);
    return buf;
}

fn send_pkt(s: *sslStream, msg: []u8) void {
    var pkt: []u8 = allocator.alloc(u8, 2 + msg.len) catch @panic("oom");
    defer allocator.free(pkt);
    if (msg.len > (1 << 16) - 1) {
        warn("msg is too long: {}, max {}\n", .{ msg.len, (1 << 16) - 1 });
        fail(s);
    }
    std.mem.writeInt(u16, pkt[0..2], @truncate(msg.len), std.builtin.Endian.big);
    @memcpy(pkt[2..], msg);

    var i: usize = 0;
    while (i < pkt.len) {
        const r = s.write(pkt[i..]) catch |e| {
            warn("error: {}\n", .{e});
            @panic("network error");
        };
        if (r == 0) break;
        i += r;
    }
    if (i == pkt.len) {
        s.flush() catch |e| {
            warn("failed to flush connection: {}\n", .{e});
            fail(s);
        };
        return;
    }
    @panic("network error");
}

fn tohexid(id: [32]u8) anyerror![]u8 {
    const hexbuf = allocator.alloc(u8, 64) catch @panic("oom");
    return std.fmt.bufPrint(hexbuf, "{x:0>64}", .{std.fmt.fmtSliceHexLower(id[0..])});
}

fn load(cfg: *const Config, path: []const u8, size: usize) ![]const u8 {
    if (posix.open(path, .{ .ACCMODE = .RDONLY }, 0)) |f| {
        defer posix.close(f);
        const key: []u8 = s_allocator.alloc(u8, @intCast(size)) catch @panic("oom");
        _ = posix.read(f, key) catch |err| {
            if (cfg.verbose) warn("cannot open {s} error: {}\n", .{ path, err });
        };
        return key;
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {s} error: {}\n", .{ path, err });
        }
        warn("failed to open: {s}\n", .{ path });
        return err;
    }
}

const CB_Ctx = struct {
    cfg: *const Config,
    s: *sslStream,
};

fn keyloader(_id: [*c]u8, arg: ?*anyopaque, _sigpk: [*c]u8, _noisepk: [*c]u8) c_int {
    var ctx: *CB_Ctx = undefined;
    if(arg) |_ctx| {
        ctx = @ptrCast(@alignCast(_ctx));
    } else {
        return 1;
    }

    const id: *[blake2b.digest_length]u8 = @ptrCast(_id);
    utils.hexdump(id[0..]);

    const r: Pubkeys = ctx.cfg.authorized_keys.get(id.*) orelse  return 1;
    const sigkey: *[sodium.crypto_sign_PUBLICKEYBYTES]u8 = @ptrCast(_sigpk);
    const noisekey: *[sodium.crypto_scalarmult_BYTES]u8 = @ptrCast(_noisepk);
    @memcpy(sigkey, r.sigkey[0..]);
    @memcpy(noisekey, r.noisekey[0..]);

    return 0;
}

const private_mode = switch (builtin.os.tag) {
    .windows => 0,
    .wasi => 0,
    else => 0o600,
};

fn store(cfg: *const Config, recid: []const u8, fieldid: []const u8, data: []const u8, new: bool) !void {
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(recid[0..], &local_id, .{ .key = cfg.record_salt });

    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    const rec_path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] }) catch @panic("oom");
    defer allocator.free(rec_path);
    if(utils.dir_exists(rec_path)) {
        if(new) return error.PathAlreadyExists;
    } else {
        posix.mkdir(rec_path, 0o700) catch |err| {
            log("failed to create {s}, error: {}\n", .{rec_path, err}, recid);
            return err;
        };
    }

    const path = mem.concat(allocator, u8, &[_][]const u8{ rec_path, "/", fieldid }) catch @panic("oom");
    defer allocator.free(path);

    const file = try std.fs.cwd().createFile(path,
                                             .{.truncate = true,
                                               .exclusive = new,
                                               .lock = .exclusive,
                                               .mode = private_mode});
    defer file.close();

    var fw = file.writer();
    try fw.writeAll(data);
}

fn open(cfg: *const Config, recid: []const u8, fieldid: []const u8) !std.fs.File {
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(recid[0..], &local_id, .{ .key = cfg.record_salt });

    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    const rec_path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] }) catch @panic("oom");
    defer allocator.free(rec_path);
    if(!utils.dir_exists(rec_path)) {
        log("rec doesn't exist {s}\n", .{rec_path}, recid);
        return error.FileNotFound;
    }

    const path = mem.concat(allocator, u8, &[_][]const u8{ rec_path, "/", fieldid }) catch @panic("oom");
    defer allocator.free(path);

    return try std.fs.cwd().openFile(path, .{});
}

fn loadx(cfg: *const Config, recid: []const u8, fieldid: []const u8, data: []u8) !void {
    const file = try open(cfg,recid,fieldid);
    var fr = file.reader();
    _ = try fr.readAll(data[0..]);
}

fn dkg(cfg: *const Config, s: *sslStream, req: *const CreateReq) *const [sodium.crypto_sign_PUBLICKEYBYTES]u8 {
    const ltsigkey: []const u8 = load(cfg, cfg.ltsigkey, sodium.crypto_sign_SECRETKEYBYTES) catch fail(s);
    const noisekey: []const u8 = load(cfg, cfg.noisekey, sodium.crypto_scalarmult_SCALARBYTES) catch fail(s);

    var peer = workaround.new_stp_dkg_peerstate();
    defer workaround.del_stp_dkg_peerstate(@ptrCast(&peer));

    const stp_ltpk: [][sodium.crypto_sign_PUBLICKEYBYTES]u8 = allocator.alloc([sodium.crypto_sign_PUBLICKEYBYTES]u8, 1) catch @panic("oom");
    const retsp = stp_dkg.stp_dkg_start_peer(@ptrCast(peer),
                                             cfg.ts_epsilon,
                                             ltsigkey.ptr,
                                             noisekey.ptr,
                                             @ptrCast(&req.msg0),
                                             @ptrCast(stp_ltpk));
    if (retsp != 0) {
        warn("failed to start stp-dkg peer (error code: {})\n", .{retsp});
        fail(s);
    }
    const n = stp_dkg.stp_dkg_peerstate_n(@ptrCast(peer)); // @as(*stp_dkg.STP_DKG_PeerState, @ptrCast(peer)).n;
    const t = stp_dkg.stp_dkg_peerstate_t(@ptrCast(peer)); // @as(*stp_dkg.STP_DKG_PeerState, @ptrCast(peer)).t;
    //warn("dkg {}/{}\n", .{t,n});
    const peer_ids: [][sodium.crypto_generichash_BYTES]u8 = allocator.alloc([sodium.crypto_generichash_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(peer_ids);
    var lt_pks: [][sodium.crypto_sign_PUBLICKEYBYTES]u8 = allocator.alloc([sodium.crypto_sign_PUBLICKEYBYTES]u8, n+1) catch @panic("oom");
    defer allocator.free(lt_pks);
    @memcpy(lt_pks[0][0..], stp_ltpk[0][0..]);
    const peer_noise_pks: [][sodium.crypto_scalarmult_BYTES]u8 = allocator.alloc([sodium.crypto_scalarmult_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(peer_noise_pks);
    const noise_outs: []*stp_dkg.Noise_XK_session_t_s = allocator.alloc(*stp_dkg.Noise_XK_session_t_s, n) catch @panic("oom");
    defer allocator.free(noise_outs);
    const noise_ins: []*stp_dkg.Noise_XK_session_t_s = allocator.alloc(*stp_dkg.Noise_XK_session_t_s, n) catch @panic("oom");
    defer allocator.free(noise_ins);
    const dealer_shares: [][toprf.TOPRF_Share_BYTES*2]u8 = allocator.alloc([toprf.TOPRF_Share_BYTES*2]u8, n) catch @panic("oom");
    defer allocator.free(dealer_shares);
    const encrypted_shares: [][stp_dkg.noise_xk_handshake3_SIZE + stp_dkg.stp_dkg_encrypted_share_SIZE]u8 =
           allocator.alloc( [stp_dkg.noise_xk_handshake3_SIZE + stp_dkg.stp_dkg_encrypted_share_SIZE]u8, n) catch @panic("oom");
    defer allocator.free(encrypted_shares);
    const share_macs: [][sodium.crypto_auth_hmacsha256_BYTES]u8 = allocator.alloc( [sodium.crypto_auth_hmacsha256_BYTES]u8, n*n) catch @panic("oom");
    defer allocator.free(share_macs);
    const dealer_commitments: [][sodium.crypto_core_ristretto255_BYTES]u8 = allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, n * n) catch @panic("oom");
    defer allocator.free(dealer_commitments);
    const k_commitments: [][sodium.crypto_core_ristretto255_BYTES]u8 = allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(k_commitments);
    const commitments_hashes: [][stp_dkg.stp_dkg_commitment_HASHBYTES]u8 = allocator.alloc([stp_dkg.stp_dkg_commitment_HASHBYTES]u8, n) catch @panic("oom");
    defer allocator.free(commitments_hashes);
    const cheaters: []stp_dkg.STP_DKG_Cheater = allocator.alloc(stp_dkg.STP_DKG_Cheater, t*t-1) catch @panic("oom");
    defer allocator.free(cheaters);
    const peer_complaints: []u16 = allocator.alloc(u16, n * n) catch @panic("oom");
    defer allocator.free(peer_complaints);
    const peer_my_complaints: []u8 = allocator.alloc(u8, n) catch @panic("oom");
    defer allocator.free(peer_my_complaints);
    const peer_last_ts: []u64 = allocator.alloc(u64, n) catch @panic("oom");
    defer allocator.free(peer_last_ts);

    var cb_ctx: CB_Ctx = .{
        .cfg = cfg,
        .s = s,
    };

    if(0!=stp_dkg.stp_dkg_peer_set_bufs(@ptrCast(peer),
                                        @alignCast(@ptrCast(peer_ids)),
                                        @alignCast(@ptrCast(&keyloader)),
                                        @alignCast(@ptrCast(&cb_ctx)),
                                        @alignCast(@ptrCast(lt_pks)),
                                        @alignCast(@ptrCast(peer_noise_pks)),
                                        @alignCast(@ptrCast(noise_outs)),
                                        @alignCast(@ptrCast(noise_ins)),
                                        @alignCast(@ptrCast(dealer_shares)),
                                        @alignCast(@ptrCast(encrypted_shares)),
                                        @alignCast(@ptrCast(share_macs)),
                                        @alignCast(@ptrCast(dealer_commitments)),
                                        @alignCast(@ptrCast(k_commitments)),
                                        @alignCast(@ptrCast(commitments_hashes)),
                                        @alignCast(@ptrCast(cheaters)),
                                        cheaters.len,
                                        @alignCast(@ptrCast(peer_complaints.ptr)),
                                        @alignCast(@ptrCast(peer_my_complaints.ptr)),
                                        @ptrCast(peer_last_ts.ptr))) {
        warn("invalid n/t parameters. aborting\n", .{});
        fail(s);
    }

    while (stp_dkg.stp_dkg_peer_not_done(@ptrCast(peer)) != 0) {
        const cur_step = @as(*stp_dkg.STP_DKG_PeerState, @ptrCast(peer)).step;
        const msglen = stp_dkg.stp_dkg_peer_input_size(@ptrCast(peer));
        //if(DEBUG) warn("[{}] input msglen: {}\n", .{cur_step, msglen});
        //var msg : []u8 = allocator.alloc(u8, stp_dkg.stp_dkg_peer_input_size(@ptrCast(peer))) catch @panic("oom");
        //defer allocator.free(msg);
        var msg: ?[*]u8 = undefined;
        var _msg: []u8 = undefined;
        if (msglen > 0) {
            _msg = read_pkt(s);
            if (msglen != _msg.len) {
                fail(s);
            }
            msg = _msg.ptr;
        } else {
            msg = null;
        }
        const resp_size = stp_dkg.stp_dkg_peer_output_size(@ptrCast(peer));
        //if(DEBUG) warn("[{}] response size: {}\n", .{cur_step, resp_size});
        const resp: []u8 = allocator.alloc(u8, resp_size) catch @panic("oom");
        defer allocator.free(resp);
        const ret = stp_dkg.stp_dkg_peer_next(@ptrCast(peer), msg, msglen, resp.ptr, resp.len);
        if(msglen>0) allocator.free(_msg);
        if (0 != ret) {
            warn("STP DKG failed with {} in step {}.\n", .{ ret, cur_step });
            stp_dkg.stp_dkg_peer_free(@ptrCast(peer));
            fail(s);
        }
        if (resp.len > 0) {
            //if(DEBUG) {
            //    warn("\nsending: ",.{});
            //    utils.hexdump(resp[0..]);
            //}
            send_pkt(s, resp);
        }
    }
    // todo handle cheaters

    var share = [_]u8{0} ** (toprf.TOPRF_Share_BYTES*2);
    workaround.extract_stp_dkg_share(@ptrCast(peer), @ptrCast(&share));
    if(DEBUG) {
        warn("share ", .{});
        utils.hexdump(share[0..]);
    }

    store(cfg, req.id[0..], "share", &share, true) catch |err| {
        log("failed to store share: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    store(cfg, req.id[0..], "commitments", mem.sliceAsBytes(k_commitments), false) catch |err| {
        log("failed to store commitments: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    store(cfg, req.id[0..], "sigkeys", mem.sliceAsBytes(lt_pks[1..]), false) catch |err| {
        log("failed to store long-term sig keys: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    store(cfg, req.id[0..], "noisekeys", mem.sliceAsBytes(peer_noise_pks), false) catch |err| {
        log("failed to store long-term noise keys: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    const params = [_]u8{n, t};
    store(cfg, req.id[0..], "params", &params, false) catch |err| {
        log("failed to store share setup: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    store(cfg, req.id[0..], "owner", &lt_pks[0], false) catch |err| {
        log("failed to store owner sig pubkey: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    var pki: [toprf.TOPRF_Share_BYTES]u8 = undefined;
    pki[0]=share[0];
    if(0!=sodium.crypto_scalarmult_ristretto255_base(pki[1..],share[1..33])) @panic("invalid share generated");
    _ = s.write(pki[0..]) catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        fail(s);
    };
    return &stp_ltpk[0];
}

fn toprf_update(cfg: *const Config, s: *sslStream, req: *const UpdateReq) void {
    const ltsigkey: []const u8 = load(cfg, cfg.ltsigkey, sodium.crypto_sign_SECRETKEYBYTES) catch fail(s);
    const noisekey: []const u8 = load(cfg, cfg.noisekey, sodium.crypto_scalarmult_SCALARBYTES) catch fail(s);

    var peer = workaround.new_toprf_update_peerstate();
    defer workaround.del_toprf_update_peerstate(@ptrCast(&peer));

    var stp_ltpk: [sodium.crypto_sign_PUBLICKEYBYTES]u8 = undefined;
    var pkid: [tupdate.toprf_keyid_SIZE]u8 = undefined;
    const retsp = tupdate.toprf_update_start_peer(@ptrCast(peer),
                                                  cfg.ts_epsilon,
                                                  ltsigkey.ptr,
                                                  noisekey.ptr,
                                                  @ptrCast(&req.msg0),
                                                  @ptrCast(&pkid),
                                                  @ptrCast(&stp_ltpk));
    if (retsp != 0) {
        warn("failed to start toprf update peer (error code: {})\n", .{retsp});
        fail(s);
    }
    // todo check if stp_ltpk is in authorized_keys
    utils.hexdump(&stp_ltpk);

    var params: [2]u8 = undefined;
    loadx(cfg, req.id[0..], "params", &params) catch |err| {
        log("failed to load share setup: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    const n = params[0];
    const t = params[1];
    warn("params {}/{}\n", .{n,t});
    workaround.toprf_update_peerstate_set_n(peer,n);
    workaround.toprf_update_peerstate_set_t(peer,t);
    const dealers = (t-1)*2 + 1;

    var lt_pks: [][sodium.crypto_sign_PUBLICKEYBYTES]u8 = allocator.alloc([sodium.crypto_sign_PUBLICKEYBYTES]u8, n+1) catch @panic("oom");
    defer allocator.free(lt_pks);
    @memcpy(lt_pks[0][0..], stp_ltpk[0..]);
    loadx(cfg, req.id[0..], "sigkeys", mem.sliceAsBytes(lt_pks[1..])) catch |err| {
        log("failed to load long-term sig keys: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    const noise_pks: [][sodium.crypto_scalarmult_BYTES]u8 = allocator.alloc([sodium.crypto_scalarmult_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(noise_pks);
    loadx(cfg, req.id[0..], "noisekeys", mem.sliceAsBytes(noise_pks)) catch |err| {
        log("failed to load long-term noise keys: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    var k0_share: [2]toprf.TOPRF_Share = undefined;
    loadx(cfg, req.id[0..], "share", mem.sliceAsBytes(&k0_share)) catch |err| {
        log("failed to load share: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    const index: u8 = k0_share[0].index;
    // todo load commitments, note there might be less than commitments if we are dynamically expanding
    const k0_commitments: [][sodium.crypto_core_ristretto255_BYTES]u8  = allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(k0_commitments);
    loadx(cfg, req.id[0..], "commitments", mem.sliceAsBytes(k0_commitments)) catch |err| {
        log("failed to load k0 commitments: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    const noise_outs: []*tupdate.Noise_XK_session_t_s = allocator.alloc(*tupdate.Noise_XK_session_t_s, n) catch @panic("oom");
    defer allocator.free(noise_outs);
    const noise_ins: []*tupdate.Noise_XK_session_t_s = allocator.alloc(*tupdate.Noise_XK_session_t_s, n) catch @panic("oom");
    defer allocator.free(noise_ins);
    const p_shares: [][toprf.TOPRF_Share_BYTES*2]u8 = allocator.alloc([toprf.TOPRF_Share_BYTES*2]u8, n) catch @panic("oom");
    defer allocator.free(p_shares);
    const p_commitments: [][sodium.crypto_core_ristretto255_BYTES]u8 = allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, n * n) catch @panic("oom");
    defer allocator.free(p_commitments);
    const p_commitment_hashes: [][tupdate.toprf_update_commitment_HASHBYTES]u8 = allocator.alloc([tupdate.toprf_update_commitment_HASHBYTES]u8, n) catch @panic("oom");
    defer allocator.free(p_commitment_hashes);
    const p_share_macs: [][sodium.crypto_auth_hmacsha256_BYTES]u8 = allocator.alloc( [sodium.crypto_auth_hmacsha256_BYTES]u8, n*n) catch @panic("oom");
    defer allocator.free(p_share_macs);
    const peer_complaints: []u16 = allocator.alloc(u16, n * n) catch @panic("oom");
    defer allocator.free(peer_complaints);
    const peer_my_complaints: []u8 = allocator.alloc(u8, n) catch @panic("oom");
    defer allocator.free(peer_my_complaints);
    const encrypted_shares: [][tupdate.noise_xk_handshake3_SIZE + tupdate.toprf_update_encrypted_shares_SIZE]u8 =
           allocator.alloc( [tupdate.noise_xk_handshake3_SIZE + tupdate.toprf_update_encrypted_shares_SIZE]u8, n) catch @panic("oom");
    defer allocator.free(encrypted_shares);
    const peer_last_ts: []u64 = allocator.alloc(u64, n) catch @panic("oom");
    defer allocator.free(peer_last_ts);
    const lambdas: [][sodium.crypto_core_ristretto255_SCALARBYTES]u8 = allocator.alloc( [sodium.crypto_core_ristretto255_SCALARBYTES]u8, dealers) catch @panic("oom");
    defer allocator.free(lambdas);
    const k0p_shares = allocator.alloc([2]toprf.TOPRF_Share, dealers) catch @panic("oom");
    defer allocator.free(k0p_shares);

    const k0p_commitments: [][sodium.crypto_core_ristretto255_BYTES]u8 = allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, dealers*(n+1)) catch @panic("oom");
    defer allocator.free(k0p_commitments);

    const zk_challenge_nonce_commitments: [][sodium.crypto_core_ristretto255_BYTES]u8 = allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(zk_challenge_nonce_commitments);
    const zk_challenge_nonces: [][2][sodium.crypto_core_ristretto255_SCALARBYTES]u8 = allocator.alloc([2][sodium.crypto_core_ristretto255_SCALARBYTES]u8, n) catch @panic("oom");
    defer allocator.free(zk_challenge_nonces);
    const zk_challenge_commitments: [][3][sodium.crypto_core_ristretto255_SCALARBYTES]u8 = allocator.alloc([3][sodium.crypto_core_ristretto255_BYTES]u8, dealers) catch @panic("oom");
    defer allocator.free(zk_challenge_commitments);
    const zk_challenge_e_i: [][sodium.crypto_core_ristretto255_SCALARBYTES]u8 = allocator.alloc([sodium.crypto_core_ristretto255_SCALARBYTES]u8, dealers) catch @panic("oom");
    defer allocator.free(zk_challenge_e_i);
    const cheaters: []tupdate.TOPRF_Update_Cheater = allocator.alloc(tupdate.TOPRF_Update_Cheater, t*t-1) catch @panic("oom");
    defer allocator.free(cheaters);

    if(0!=tupdate.toprf_update_peer_set_bufs(@ptrCast(peer),
                                             index, n, t,
                                             @alignCast(@ptrCast(&k0_share)),
                                             @alignCast(@ptrCast(k0_commitments)),
                                             @alignCast(@ptrCast(lt_pks)),
                                             @alignCast(@ptrCast(noise_pks)),
                                             @alignCast(@ptrCast(noise_outs)),
                                             @alignCast(@ptrCast(noise_ins)),
                                             @alignCast(@ptrCast(p_shares)),
                                             @alignCast(@ptrCast(p_commitments)),
                                             @alignCast(@ptrCast(p_commitment_hashes)),
                                             @alignCast(@ptrCast(p_share_macs)),
                                             @alignCast(@ptrCast(encrypted_shares)),
                                             @alignCast(@ptrCast(cheaters)),
                                             cheaters.len,
                                             @alignCast(@ptrCast(lambdas)),
                                             @alignCast(@ptrCast(k0p_shares)),
                                             @alignCast(@ptrCast(k0p_commitments)),
                                             @alignCast(@ptrCast(zk_challenge_nonce_commitments)),
                                             @alignCast(@ptrCast(zk_challenge_nonces)),
                                             @alignCast(@ptrCast(zk_challenge_commitments)),
                                             @alignCast(@ptrCast(zk_challenge_e_i)),
                                             @alignCast(@ptrCast(peer_complaints.ptr)),
                                             @alignCast(@ptrCast(peer_my_complaints.ptr)),
                                             @ptrCast(peer_last_ts.ptr))) {
        warn("invalid n/t parameters. aborting\n", .{});
        fail(s);
    }

    while (tupdate.toprf_update_peer_not_done(@ptrCast(peer)) != 0) {
        const cur_step = tupdate.toprf_update_peerstate_step(@ptrCast(peer));
        const msglen = tupdate.toprf_update_peer_input_size(@ptrCast(peer));
        //if(DEBUG) warn("[{}] input msglen: {}\n", .{cur_step, msglen});
        //var msg : []u8 = allocator.alloc(u8, tupdate.toprf_update_peer_input_size(@ptrCast(peer))) catch @panic("oom");
        //defer allocator.free(msg);
        var msg: ?[*]u8 = undefined;
        var _msg: []u8 = undefined;
        if (msglen > 0) {
            _msg = read_pkt(s);
            if (msglen != _msg.len) {
                fail(s);
            }
            msg = _msg.ptr;
        } else {
            msg = null;
        }
        const resp_size = tupdate.toprf_update_peer_output_size(@ptrCast(peer));
        //if(DEBUG) warn("[{}] response size: {}\n", .{cur_step, resp_size});
        const resp: []u8 = allocator.alloc(u8, resp_size) catch @panic("oom");
        defer allocator.free(resp);
        const ret = tupdate.toprf_update_peer_next(@ptrCast(peer), msg, msglen, resp.ptr, resp.len);
        if(msglen>0) allocator.free(_msg);
        if (0 != ret) {
            warn("TOPRF Update failed with {} in step {}.\n", .{ ret, cur_step });
            tupdate.toprf_update_peer_free(@ptrCast(peer));
            fail(s);
        }
        if (resp.len > 0) {
            //if(DEBUG) {
            //    warn("\nsending: ",.{});
            //    utils.hexdump(resp[0..]);
            //}
            send_pkt(s, resp);
        }
    }

    const share: *const [toprf.TOPRF_Share_BYTES*2]u8 = @ptrCast(tupdate.toprf_update_peerstate_share(@ptrCast(peer)));
    if(DEBUG) {
        warn("share ", .{});
        utils.hexdump(share[0..]);
    }
    store(cfg, req.id[0..], "share", share, false) catch |err| {
        log("failed to store share: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    const commitments = tupdate.toprf_update_peerstate_commitments(@ptrCast(peer))[0..sodium.crypto_scalarmult_ristretto255_BYTES*n];
    store(cfg, req.id[0..], "commitments", commitments, false) catch |err| {
        log("failed to store commitments: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    var pki: [toprf.TOPRF_Share_BYTES]u8 = undefined;
    pki[0]=share[0];
    if(0!=sodium.crypto_scalarmult_ristretto255_base(pki[1..],share[1..33])) @panic("invalid share generated");
    _ = s.write(pki[0..]) catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        fail(s);
    };
}

fn handle_read_err(err: anyerror, s: *sslStream) noreturn {
    if (err == ssl.BearError.UNSUPPORTED_VERSION) {
        warn("{} unsupported TLS version. aborting.\n", .{conn.address});
        s.close() catch unreachable;
        posix.exit(0);
    } else if (err == ssl.BearError.UNKNOWN_ERROR_582 or err == ssl.BearError.UNKNOWN_ERROR_552) {
        warn("{} unknown TLS error: {}. aborting.\n", .{ conn.address, err });
        s.close() catch unreachable;
        posix.exit(0);
    } else if (err == ssl.BearError.BAD_VERSION) {
        warn("{} bad TLS version. aborting.\n", .{conn.address});
        s.close() catch unreachable;
        posix.exit(0);
    }
    warn("read error: {}\n", .{err});
    @panic("network error");
}

fn read_req(s: *sslStream, comptime T: type, op: []const u8) anyerror!*T {
    var buf = allocator.alloc(u8, @sizeOf(T)) catch @panic("oom");
    const buflen = s.read(buf[0..]) catch |err| {
        handle_read_err(err, s);
        return err;
    };

    if (buflen != buf.len) {
        log("invalid {s} request. aborting.\n", .{op}, "");
        fail(s);
    }
    const req: *T = @ptrCast(buf[0..]);

    log("{} op {s}\n", .{ conn.address, op }, &req.id);
    return req;
}

fn auth(cfg: *const Config, s: *sslStream, op: KlutshnikPerms, pk: *ed25519.PublicKey, reqbuf: []const u8) void {
    const reqid = reqbuf[0..32];

    var owner: [sodium.crypto_sign_PUBLICKEYBYTES]u8 = undefined;
    loadx(cfg, reqid, "owner", &owner) catch |err| {
        log("failed to load owner pubkey: {}\n", .{err}, reqid);
        fail(s);
    };
    const owner_pk = ed25519.PublicKey.fromBytes(owner) catch |err| {
        log("invalid pubkey for owner {x:0>64}: {}\n", .{owner, err}, reqid);
        fail(s);
    };

    const siglen = ed25519.Signature.encoded_length;
    if(op==KlutshnikPerms.OWNER) {
        pk.* = owner_pk;
    } else {
        // check if pk has permission
        // auth file load
        const authfd = open(cfg, reqid, "auth") catch |err| {
            log("failed to open auth file: {}\n", .{err}, reqid);
            fail(s);
        };
        var auth_size: u64 = undefined;
        if(authfd.stat()) |st| {
            auth_size = st.size;
        } else |err| {
            log("failed to stat auth file: {}\n", .{err}, reqid);
            fail(s);
        }
        const authbuf= allocator.alloc(u8, auth_size) catch @panic("oom");
        var fr = authfd.reader();
        _ = fr.readAll(authbuf[0..]) catch |err| {
            log("failed to load auth file: {}\n", .{err}, reqid);
            fail(s);
        };
        authfd.close();
        const auth_sig = ed25519.Signature.fromBytes(authbuf[0..siglen].*);
        auth_sig.verify(authbuf[siglen..], owner_pk) catch |err| {
            log("auth fail: {}\n", .{err}, reqbuf[0..sodium.crypto_generichash_BYTES]);
            fail(s);
        };

        var ptr: usize = siglen;
        while(ptr < auth_size) {
            const _pk = ptr;
            ptr += sodium.crypto_sign_PUBLICKEYBYTES;
            const perm = ptr;
            ptr+=1;
            if(mem.eql(u8, authbuf[_pk.._pk+32],&pk.toBytes())) {
                if(authbuf[perm] & @intFromEnum(op) == @intFromEnum(op)) break;
                fail(s);
            }
        }
    }

    var nonce : [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    send_pkt(s, nonce[0..]);

    const data = mem.concat(allocator, u8, &[_][]const u8{ reqbuf, nonce[0..] }) catch @panic("oom");
    const sigbuf = read_pkt(s);
    defer(allocator.free(sigbuf));
    if(sigbuf.len!=ed25519.Signature.encoded_length) {
        log("auth response signature has invalid size: {}\n", .{sigbuf.len}, reqbuf[0..sodium.crypto_generichash_BYTES]);
        fail(s);
    }
    const sig = ed25519.Signature.fromBytes(sigbuf[0..siglen].*);
    sig.verify(data, pk.*) catch |err| {
        log("auth fail using pk {x:0>64}: {}\n", .{std.fmt.fmtSliceHexLower(&pk.toBytes()), err}, reqbuf[0..sodium.crypto_generichash_BYTES]);
        warn("sig: ", .{}); utils.hexdump(sigbuf[0..siglen]);
        warn("data: ", .{}); utils.hexdump(data[0..]);
        warn("pk: ", .{}); utils.hexdump(&pk.toBytes());
        fail(s);
    };

    log("successfully authenticated using pk {x:0>64}\n", .{std.fmt.fmtSliceHexLower(&pk.toBytes())}, reqbuf[0..sodium.crypto_generichash_BYTES]);
}

fn create(cfg: *const Config, s: *sslStream, req: *const CreateReq) void {
    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], &local_id, .{ .key = cfg.record_salt });
    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] }) catch @panic("oom");
    defer allocator.free(path);

    if (utils.dir_exists(path)) fail(s);

    const owner_pk: *const [sodium.crypto_sign_PUBLICKEYBYTES]u8 = dkg(cfg, s, req);
    const pk = ed25519.PublicKey.fromBytes(owner_pk.*) catch |err| {
        log("invalid pubkey for owner {x:0>64}: {}\n", .{owner_pk, err}, &req.id);
        fail(s);
    };
    const auth_buf = read_pkt(s);
    defer(allocator.free(auth_buf));
    const siglen = ed25519.Signature.encoded_length;
    const sig = ed25519.Signature.fromBytes(auth_buf[0..siglen].*);
    sig.verify(auth_buf[siglen..], pk) catch |err| {
        log("fail auth data not signed by owner: {}\n", .{err}, &req.id);
        fail(s);
    };
    store(cfg, req.id[0..], "auth", auth_buf, false) catch |err| {
        log("failed to store auth: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    log("success creating new key for owner {}\n", .{std.fmt.fmtSliceHexLower(owner_pk)}, &req.id);
}

fn update(cfg: *const Config, s: *sslStream, req: *const UpdateReq) void {
    var pk = ed25519.PublicKey.fromBytes(req.pk) catch |err| {
        log("invalid pubkey in update request: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    auth(cfg, s, KlutshnikPerms.UPDATE, &pk, mem.asBytes(req));

    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], &local_id, .{ .key = cfg.record_salt });
    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] }) catch @panic("oom");
    defer allocator.free(path);

    if(!utils.dir_exists(path)) fail(s);

    toprf_update(cfg, s, req);
    log("success updating key by {}\n", .{std.fmt.fmtSliceHexLower(&req.pk)}, &req.id);
}

fn decrypt(cfg: *const Config, s: *sslStream, req: *const DecryptReq) void {
    var pk = ed25519.PublicKey.fromBytes(req.pk) catch |err| {
        log("invalid pubkey in decrypt request: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    auth(cfg, s, KlutshnikPerms.DECRYPT, &pk, mem.asBytes(req));

    var k0_share: [2]toprf.TOPRF_Share = undefined;
    loadx(cfg, req.id[0..], "share", mem.sliceAsBytes(&k0_share)) catch |err| {
        log("failed to load share: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    if(0==sodium.crypto_core_ristretto255_is_valid_point(&req.alpha)) fail(s);
    var response: [2][1+sodium.crypto_core_ristretto255_BYTES]u8 = undefined;
    response[0][0]=k0_share[0].index;
    response[1][0]=k0_share[0].index;
    if(0!=sodium.crypto_scalarmult_ristretto255(response[0][1..], &k0_share[0].value, &req.alpha)) fail(s);

    if(0==sodium.crypto_core_ristretto255_is_valid_point(&req.verifier)) fail(s);
    if(0!=sodium.crypto_scalarmult_ristretto255(response[1][1..], &k0_share[0].value, &req.verifier)) fail(s);

    _ = s.write(mem.asBytes(response[0..])) catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        fail(s);
    };
    log("success decrypt by {}\n", .{std.fmt.fmtSliceHexLower(&req.pk)}, &req.id);
}

fn delete(cfg: *const Config, s: *sslStream, req: *const DeleteReq) void {
    var pk = ed25519.PublicKey.fromBytes(req.pk) catch |err| {
        log("invalid pubkey in delete request: {}\n", .{err}, req.id[0..]);
        fail(s);
    };
    auth(cfg, s, KlutshnikPerms.DELETE, &pk, mem.asBytes(req));

    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], &local_id, .{ .key = cfg.record_salt });
    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] }) catch @panic("oom");
    defer allocator.free(path);

    if (!utils.dir_exists(path)) fail(s);

    std.fs.cwd().deleteTree(path) catch |err| {
        log("failed to delete record {s}: {}\n", .{path, err}, hexid);
        fail(s);
    };

    _ = s.write("ok") catch |err| {
        log("failed to write confirmation of deletion: {}\n", .{err}, hexid);
        fail(s);
    };
    s.flush() catch |err| {
        log("failed to flush confirmation of deletion: {}\n", .{err}, hexid);
        fail(s);
    };
    log("success decrypt by {}\n", .{std.fmt.fmtSliceHexLower(&req.pk)}, &req.id);
}

fn modauth(cfg: *const Config, s: *sslStream, req: *const ModAuthReq) void {
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], &local_id, .{ .key = cfg.record_salt });
    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    const record = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] }) catch @panic("oom");
    defer allocator.free(record);

    if (!utils.dir_exists(record)) fail(s);

    ////////
    var pk : ed25519.PublicKey = undefined;
    auth(cfg, s, KlutshnikPerms.OWNER, &pk,mem.asBytes(req));

    // auth file load
    const authfd = open(cfg, &req.id, "auth") catch |err| {
        log("failed to open auth file: {}\n", .{err}, &req.id);
        fail(s);
    };
    var auth_size: u64 = undefined;
    if(authfd.stat()) |st| {
        auth_size = st.size;
    } else |err| {
        log("failed to stat auth file: {}\n", .{err}, &req.id);
        fail(s);
    }
    const authbuf= allocator.alloc(u8, auth_size) catch @panic("oom");
    var fr = authfd.reader();
    _ = fr.readAll(authbuf[0..]) catch |err| {
        log("failed to load auth file: {}\n", .{err}, &req.id);
        fail(s);
    };
    send_pkt(s, authbuf);

    if(req.readonly == 1) {
        log("list auth success by {}\n", .{std.fmt.fmtSliceHexLower(&pk.toBytes())}, &req.id);
        return;
    }

    const authbuf2 = read_pkt(s);
    defer(allocator.free(authbuf2));

    const siglen = ed25519.Signature.encoded_length;
    const auth_sig = ed25519.Signature.fromBytes(authbuf2[0..siglen].*);
    auth_sig.verify(authbuf2[siglen..], pk) catch |err| {
        log("auth fail: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    store(cfg, req.id[0..], "auth", authbuf2, false) catch |err| {
        log("failed to store auth: {}\n", .{err}, req.id[0..]);
        fail(s);
    };

    log("mod auth success by {}\n", .{std.fmt.fmtSliceHexLower(&pk.toBytes())}, &req.id);
}

fn handler(cfg: *const Config, s: *sslStream) !void {
    var op_buf: [1]u8 = undefined;
    _ = s.read(op_buf[0..]) catch |err| {
        handle_read_err(err, s);
    };
    const op = @as(KlutshnikOp, @enumFromInt(op_buf[0]));
    switch (op) {
        KlutshnikOp.CREATE => {
            const req: *CreateReq = read_req(s, CreateReq, "create"[0..]) catch |e| {
                warn("read create request failed with {}", .{e});
                fail(s);
            };
            defer allocator.free(@as(*[@sizeOf(CreateReq)]u8, @ptrCast(req)));
            create(cfg, s, req);
        },
        KlutshnikOp.DECRYPT => {
            const req: *DecryptReq = read_req(s, DecryptReq, "decrypt"[0..]) catch |e| {
                warn("read decrypt request failed with {}", .{e});
                fail(s);
            };
            defer allocator.free(@as(*[@sizeOf(DecryptReq)]u8, @ptrCast(req)));
            decrypt(cfg, s, req);
        },
        KlutshnikOp.DELETE => {
            const req: *DeleteReq = read_req(s, DeleteReq, "delete"[0..]) catch |e| {
                warn("read delete request failed with {}", .{e});
                fail(s);
            };
            defer allocator.free(@as(*[@sizeOf(DeleteReq)]u8, @ptrCast(req)));
            delete(cfg, s, req);
        },
        KlutshnikOp.UPDATE => {
            const req: *UpdateReq = read_req(s, UpdateReq, "update"[0..]) catch |e| {
                warn("read update request failed with {}", .{e});
                fail(s);
            };
            defer allocator.free(@as(*[@sizeOf(UpdateReq)]u8, @ptrCast(req)));
            update(cfg, s, req);
        },
        KlutshnikOp.MODAUTH => {
            const req: *ModAuthReq = read_req(s, ModAuthReq, "mod auth"[0..]) catch |e| {
                warn("read mod auth request failed with {}", .{e});
                fail(s);
            };
            defer allocator.free(@as(*[@sizeOf(ModAuthReq)]u8, @ptrCast(req)));
            modauth(cfg, s, req);
        },
        _ => {
            if (cfg.verbose) warn("{} invalid op({}). aborting.\n", .{ conn.address, op });
        },
    }
    try s.close();
    posix.exit(0);
}

/// classical forking server with tcp connection wrapped by bear ssl
/// number of childs is configurable, as is the listening IP address and port
pub fn main() !void {
    try stdout.print("starting up klutshnik server\n", .{});
    try bw.flush(); // don't forget to flush!

    if(DEBUG) {
        oprf_utils.debug = 1;
        stp_dkg.log_file = @ptrCast(stdio.fdopen(2,"w"));
    }

    const cfg = try loadcfg();

    if (!utils.dir_exists(cfg.datadir)) {
        posix.mkdir(cfg.datadir, 0o700) catch |err| {
            log("failed to create {s}, error: {}\n", .{cfg.datadir, err}, "");
            posix.exit(1);
        };
    }

    const sk: *ssl.c.private_key = ssl.c.read_private_key(@ptrCast(cfg.ssl_key));

    var certs_len: usize = undefined;
    const certs: *ssl.c.br_x509_certificate = ssl.c.read_certificates(@ptrCast(cfg.ssl_cert), &certs_len);

    const addresses = try std.net.getAddressList(allocator, cfg.address, cfg.port);
    defer addresses.deinit();
    for (addresses.addrs) |addr| {
        var addrtype: *const [4:0]u8 = undefined;
        switch (addr.any.family) {
            posix.AF.INET => addrtype = "ipv4",
            posix.AF.INET6 => addrtype = "ipv6",
            posix.AF.UNIX => addrtype = "unix",
            else => unreachable,
        }
        warn("addr: {s}, {}\n", .{ addrtype, addr });
    }

    const addr = try net.Address.parseIp(cfg.address, cfg.port);

    var srv = addr.listen(.{ .reuse_address = true }) catch |err| switch (err) {
        error.AddressInUse => {
            warn("port {} already in use.", .{cfg.port});
            posix.exit(1);
        },
        else => {
            return err;
            //unreachable,
        },
    };
    warn("{} listening on {}\n", .{std.os.linux.getpid(), addr});

    const to = posix.timeval{
        .tv_sec = cfg.timeout,
        .tv_usec = 0
    };
    try posix.setsockopt(srv.stream.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&to));
    try posix.setsockopt(srv.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&to));

    var kids = BufSet.init(allocator);

    while (true) {
        if (srv.accept()) |c| {
            conn = c;
            log("new connection\n", .{}, "");
        } else |e| {
            if (e == error.WouldBlock) {
                while (true) {
                    const Status = if (builtin.link_libc) c_int else u32;
                    var status: Status = undefined;
                    const rc = posix.system.waitpid(-1, &status, posix.system.W.NOHANG);
                    if (rc > 0) {
                        kids.remove(mem.asBytes(&rc));
                        if (cfg.verbose) warn("removing kid {} from pool\n", .{rc});
                    } else break;
                }
                continue;
            }
            unreachable;
        }

        while (kids.count() >= cfg.max_kids) {
            log("pool full, waiting for kid to die\n", .{}, "");
            const pid = posix.waitpid(-1, 0).pid;
            log("wait returned: {}\n", .{pid}, "");
            kids.remove(mem.asBytes(&pid));
        }

        var pid = try posix.fork();
        switch (pid) {
            0 => {
                setSigHandler();
                var sc: ssl.c.br_ssl_server_context = undefined;
                //c.br_ssl_server_init_full_ec(&sc, certs, certs_len, c.BR_KEYTYPE_EC, &sk.key.ec);
                ssl.c.br_ssl_server_init_minf2c(&sc, certs, certs_len, &sk.key.ec);
                var iobuf: [ssl.c.BR_SSL_BUFSIZE_BIDI]u8 = undefined;
                ssl.c.br_ssl_engine_set_buffer(&sc.eng, &iobuf, iobuf.len, 1);
                // * Reset the server context, for a new handshake.
                if (ssl.c.br_ssl_server_reset(&sc) == 0) {
                    return ssl.convertError(ssl.c.br_ssl_engine_last_error(&sc.eng));
                }
                var s = ssl.initStream(&sc.eng, &conn.stream, &conn.stream);
                handler(&cfg, &s) catch |err| {
                    if (err == error.WouldBlock or err == error.IO) {
                        if (cfg.verbose) warn("timeout, abort.\n", .{});
                        _ = std.os.linux.shutdown(conn.stream.handle, std.os.linux.SHUT.RDWR);
                        conn.stream.close();
                    } else {
                        return err;
                    }
                };
                posix.exit(0);
            },
            else => {
                try kids.insert(mem.asBytes(&pid));
                conn.stream.close();
            },
        }
    }
}
