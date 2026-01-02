/// An SSH terminfo entry cache that stores its cache data on
/// disk. The cache only stores metadata (hostname, terminfo value,
/// etc.) and does not store any sensitive data.
const DiskCache = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = @import("../../quirks.zig").inlineAssert;
const Allocator = std.mem.Allocator;
const internal_os = @import("../../os/main.zig");
const xdg = internal_os.xdg;
const TempDir = internal_os.TempDir;
const Entry = @import("Entry.zig");

// 512KB - sufficient for approximately 10k entries
const MAX_CACHE_SIZE = 512 * 1024;

/// Path to a file where the cache is stored.
path: []const u8,

pub const DefaultPathError = Allocator.Error || error{
    /// The general error that is returned for any filesystem error
    /// that may have resulted in the XDG lookup failing.
    XdgLookupFailed,
};

pub const Error = error{ CacheIsLocked, HostnameIsInvalid, InvalidCachePath, TerminfoUnavailable };

/// Returns the default path for the cache for a given program.
///
/// On all platforms, this is `${XDG_STATE_HOME}/ghostty/ssh_cache`.
///
/// The returned value is allocated and must be freed by the caller.
pub fn defaultPath(
    alloc: Allocator,
    program: []const u8,
) DefaultPathError![]const u8 {
    const state_dir: []const u8 = xdg.state(
        alloc,
        .{ .subdir = program },
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.XdgLookupFailed,
    };
    defer alloc.free(state_dir);
    return try std.fs.path.join(alloc, &.{ state_dir, "ssh_cache" });
}

/// Clear all cache data stored in the disk cache.
/// This removes the cache file from disk, effectively clearing all cached
/// SSH terminfo entries.
pub fn clear(self: DiskCache) !void {
    std.fs.cwd().deleteFile(self.path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

pub const AddResult = enum { added, updated };

/// Add or update a hostname entry in the cache.
/// Returns AddResult.added for new entries or AddResult.updated for existing ones.
/// The cache file is created if it doesn't exist with secure permissions (0600).
pub fn add(
    self: DiskCache,
    alloc: Allocator,
    hostname: []const u8,
) !AddResult {
    if (!isValidCacheKey(hostname)) return error.HostnameIsInvalid;

    // Generate current terminfo hash
    const terminfo_hash = generateTerminfoHash(alloc) catch |err| {
        std.log.warn("Failed to generate terminfo hash: {}", .{err});
        // Fall back to version string if hash generation fails
        const terminfo_copy = try alloc.dupe(u8, "xterm-ghostty");
        return addWithHash(self, alloc, hostname, terminfo_copy);
    };
    defer alloc.free(terminfo_hash);

    return addWithHash(self, alloc, hostname, terminfo_hash);
}

// Internal helper that does the actual adding
fn addWithHash(
    self: DiskCache,
    alloc: Allocator,
    hostname: []const u8,
    terminfo_hash: []const u8,
) !AddResult {
    // Create cache directory if needed
    if (std.fs.path.dirname(self.path)) |dir| {
        std.fs.cwd().makePath(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // Open or create cache file with secure permissions
    const file = std.fs.createFileAbsolute(self.path, .{
        .read = true,
        .truncate = false,
        .mode = 0o600,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => blk: {
            const existing_file = try std.fs.openFileAbsolute(
                self.path,
                .{ .mode = .read_write },
            );
            errdefer existing_file.close();
            try fixupPermissions(existing_file);
            break :blk existing_file;
        },
        else => return err,
    };
    defer file.close();

    // Lock
    // Causes a compile failure in the Zig std library on Windows, see:
    // https://github.com/ziglang/zig/issues/18430
    if (comptime builtin.os.tag != .windows) _ = file.tryLock(.exclusive) catch return error.CacheIsLocked;
    defer if (comptime builtin.os.tag != .windows) file.unlock();

    var entries = try readEntries(alloc, file);
    defer deinitEntries(alloc, &entries);

    // Add or update entry
    const gop = try entries.getOrPut(hostname);
    const result: AddResult = if (!gop.found_existing) add: {
        const hostname_copy = try alloc.dupe(u8, hostname);
        errdefer alloc.free(hostname_copy);
        const hash_copy = try alloc.dupe(u8, terminfo_hash);
        errdefer alloc.free(hash_copy);

        gop.key_ptr.* = hostname_copy;
        gop.value_ptr.* = .{
            .hostname = gop.key_ptr.*,
            .timestamp = std.time.timestamp(),
            .terminfo_version = hash_copy,
        };
        break :add .added;
    } else update: {
        // Check if hash changed
        const hash_changed = !std.mem.eql(u8, gop.value_ptr.terminfo_version, terminfo_hash);

        if (hash_changed) {
            // Update hash if it changed
            alloc.free(gop.value_ptr.terminfo_version);
            const hash_copy = try alloc.dupe(u8, terminfo_hash);
            gop.value_ptr.terminfo_version = hash_copy;
        }

        // Always update timestamp
        gop.value_ptr.timestamp = std.time.timestamp();
        break :update .updated;
    };

    try self.writeCacheFile(alloc, entries, null);
    return result;
}

/// Remove a hostname entry from the cache.
/// No error is returned if the hostname doesn't exist or the cache file is missing.
pub fn remove(
    self: DiskCache,
    alloc: Allocator,
    hostname: []const u8,
) !void {
    if (!isValidCacheKey(hostname)) return error.HostnameIsInvalid;

    // Open our file
    const file = std.fs.openFileAbsolute(
        self.path,
        .{ .mode = .read_write },
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer file.close();
    try fixupPermissions(file);

    // Lock
    // Causes a compile failure in the Zig std library on Windows, see:
    // https://github.com/ziglang/zig/issues/18430
    if (comptime builtin.os.tag != .windows) _ = file.tryLock(.exclusive) catch return error.CacheIsLocked;
    defer if (comptime builtin.os.tag != .windows) file.unlock();

    // Read existing entries
    var entries = try readEntries(alloc, file);
    defer deinitEntries(alloc, &entries);

    // Remove the entry if it exists and ensure we free the memory
    if (entries.fetchRemove(hostname)) |kv| {
        assert(kv.key.ptr == kv.value.hostname.ptr);
        alloc.free(kv.value.hostname);
        alloc.free(kv.value.terminfo_version);
    }

    try self.writeCacheFile(alloc, entries, null);
}

/// Check if a hostname exists in the cache AND has matching terminfo hash.
/// Returns false if the cache file doesn't exist or hash doesn't match.
pub fn contains(
    self: DiskCache,
    alloc: Allocator,
    hostname: []const u8,
) !bool {
    if (!isValidCacheKey(hostname)) return error.HostnameIsInvalid;

    // Open our file
    const file = std.fs.openFileAbsolute(
        self.path,
        .{},
    ) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close();

    // Read existing entries
    var entries = try readEntries(alloc, file);
    defer deinitEntries(alloc, &entries);

    const entry = entries.get(hostname) orelse return false;

    // Generate current terminfo hash
    const current_hash = generateTerminfoHash(alloc) catch {
        // If we can't generate hash, fall back to simple existence check
        return true;
    };
    defer alloc.free(current_hash);

    // Verify hash matches
    return std.mem.eql(u8, entry.terminfo_version, current_hash);
}

fn fixupPermissions(file: std.fs.File) (std.fs.File.StatError || std.fs.File.ChmodError)!void {
    // Windows does not support chmod
    if (comptime builtin.os.tag == .windows) return;

    // Ensure file has correct permissions (readable/writable by
    // owner only)
    const stat = try file.stat();
    if (stat.mode & 0o777 != 0o600) {
        try file.chmod(0o600);
    }
}

fn writeCacheFile(
    self: DiskCache,
    alloc: Allocator,
    entries: std.StringHashMap(Entry),
    expire_days: ?u32,
) !void {
    // Get directory containing cache file
    const cache_dir = std.fs.path.dirname(self.path) orelse return error.InvalidCachePath;

    // Create cache directory if needed
    std.fs.cwd().makePath(cache_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Open cache directory
    var dir = try std.fs.openDirAbsolute(cache_dir, .{});
    defer dir.close();

    // Create temp file in SAME directory as cache (not /tmp)
    const tmp_name = try std.fmt.allocPrint(alloc, ".ssh-cache.tmp.{d}", .{std.time.timestamp()});
    defer alloc.free(tmp_name);

    const tmp_file = try dir.createFile(tmp_name, .{ .mode = 0o600 });
    defer tmp_file.close();

    // Write entries
    var buf: [1024]u8 = undefined;
    var writer = tmp_file.writer(&buf);
    var iter = entries.iterator();
    while (iter.next()) |kv| {
        if (kv.value_ptr.isExpired(expire_days)) continue;
        try kv.value_ptr.format(&writer.interface);
    }
    try writer.interface.flush();

    // Get absolute path for rename
    const tmp_path = try dir.realpathAlloc(alloc, tmp_name);
    defer alloc.free(tmp_path);

    // Atomic rename (now on same filesystem)
    try std.fs.renameAbsolute(tmp_path, self.path);
}

/// Generate SHA256 hash of current xterm-ghostty terminfo.
/// Returns hex-encoded hash string that must be freed by caller.
/// Falls back to simple version string if infocmp is unavailable.
fn generateTerminfoHash(alloc: Allocator) ![]u8 {
    // Run infocmp to get terminfo data
    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = &[_][]const u8{ "infocmp", "-x", "xterm-ghostty" },
    }) catch |err| {
        std.log.warn("Failed to run infocmp: {}", .{err});
        return error.TerminfoUnavailable;
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.term.Exited != 0) {
        return error.TerminfoUnavailable;
    }

    // Hash the terminfo output
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(result.stdout);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    // Convert to hex string
    return try std.fmt.allocPrint(alloc, "{x}", .{hash});
}

/// List all entries in the cache.
/// The returned HashMap must be freed using `deinitEntries`.
/// Returns an empty map if the cache file doesn't exist.
pub fn list(
    self: DiskCache,
    alloc: Allocator,
) !std.StringHashMap(Entry) {
    // Open our file
    const file = std.fs.openFileAbsolute(
        self.path,
        .{},
    ) catch |err| switch (err) {
        error.FileNotFound => return .init(alloc),
        else => return err,
    };
    defer file.close();
    return readEntries(alloc, file);
}

/// Free memory allocated by the `list` function.
/// This must be called to properly deallocate all entry data.
pub fn deinitEntries(
    alloc: Allocator,
    entries: *std.StringHashMap(Entry),
) void {
    // All our entries we dupe the memory owned by the hostname and the
    // terminfo, and we always match the hostname key and value.
    var it = entries.iterator();
    while (it.next()) |entry| {
        assert(entry.key_ptr.*.ptr == entry.value_ptr.hostname.ptr);
        alloc.free(entry.value_ptr.hostname);
        alloc.free(entry.value_ptr.terminfo_version);
    }
    entries.deinit();
}

fn readEntries(
    alloc: Allocator,
    file: std.fs.File,
) !std.StringHashMap(Entry) {
    var reader = file.reader(&.{});
    const content = try reader.interface.allocRemaining(
        alloc,
        .limited(MAX_CACHE_SIZE),
    );
    defer alloc.free(content);

    var entries = std.StringHashMap(Entry).init(alloc);
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        const entry = Entry.parse(trimmed) orelse continue;

        // Always allocate hostname first to avoid key pointer confusion
        const hostname = try alloc.dupe(u8, entry.hostname);
        errdefer alloc.free(hostname);

        const gop = try entries.getOrPut(hostname);
        if (!gop.found_existing) {
            const terminfo_copy = try alloc.dupe(u8, entry.terminfo_version);
            gop.value_ptr.* = .{
                .hostname = hostname,
                .timestamp = entry.timestamp,
                .terminfo_version = terminfo_copy,
            };
        } else {
            // Don't need the copy since entry already exists
            alloc.free(hostname);

            // Handle duplicate entries - keep newer timestamp
            if (entry.timestamp > gop.value_ptr.timestamp) {
                gop.value_ptr.timestamp = entry.timestamp;
                if (!std.mem.eql(
                    u8,
                    gop.value_ptr.terminfo_version,
                    entry.terminfo_version,
                )) {
                    alloc.free(gop.value_ptr.terminfo_version);
                    const terminfo_copy = try alloc.dupe(u8, entry.terminfo_version);
                    gop.value_ptr.terminfo_version = terminfo_copy;
                }
            }
        }
    }

    return entries;
}

// Supports both standalone hostnames and user@hostname format
fn isValidCacheKey(key: []const u8) bool {
    if (key.len == 0) return false;

    // Check for user@hostname format
    if (std.mem.indexOfScalar(u8, key, '@')) |at_pos| {
        const user = key[0..at_pos];
        const hostname = key[at_pos + 1 ..];
        return isValidUser(user) and isValidHost(hostname);
    }

    return isValidHost(key);
}

// Checks if a host is a valid hostname or IP address
fn isValidHost(host: []const u8) bool {
    // First check for valid hostnames because this is assumed to be the more
    // likely ssh host format.
    if (internal_os.hostname.isValid(host)) {
        return true;
    }

    // We also accept valid IP addresses. In practice, IPv4 addresses are also
    // considered valid hostnames due to their overlapping syntax, so we can
    // simplify this check to be IPv6-specific.
    if (std.net.Address.parseIp6(host, 0)) |_| {
        return true;
    } else |_| {
        return false;
    }
}

fn isValidUser(user: []const u8) bool {
    if (user.len == 0 or user.len > 64) return false;
    for (user) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return false,
        }
    }
    return true;
}

test "disk cache default path" {
    const testing = std.testing;
    const alloc = std.testing.allocator;

    const path = try DiskCache.defaultPath(alloc, "ghostty");
    defer alloc.free(path);
    try testing.expect(path.len > 0);
}

test "disk cache clear" {
    const testing = std.testing;
    const alloc = testing.allocator;

    // Create our path
    var td: TempDir = try .init();
    defer td.deinit();
    var buf: [4096]u8 = undefined;
    {
        var file = try td.dir.createFile("cache", .{});
        defer file.close();
        var file_writer = file.writer(&buf);
        try file_writer.interface.writeAll("HELLO!");
    }
    const path = try td.dir.realpathAlloc(alloc, "cache");
    defer alloc.free(path);

    // Setup our cache
    const cache: DiskCache = .{ .path = path };
    try cache.clear();

    // Verify the file is gone
    try testing.expectError(
        error.FileNotFound,
        td.dir.openFile("cache", .{}),
    );
}

test "disk cache operations" {
    const testing = std.testing;
    const alloc = testing.allocator;

    // Create our path
    var td: TempDir = try .init();
    defer td.deinit();
    var buf: [4096]u8 = undefined;
    {
        var file = try td.dir.createFile("cache", .{});
        defer file.close();
        var file_writer = file.writer(&buf);
        const writer = &file_writer.interface;
        try writer.writeAll("HELLO!");
        try writer.flush();
    }
    const path = try td.dir.realpathAlloc(alloc, "cache");
    defer alloc.free(path);

    // Setup our cache
    const cache: DiskCache = .{ .path = path };
    try testing.expectEqual(
        AddResult.added,
        try cache.add(alloc, "example.com"),
    );
    try testing.expectEqual(
        AddResult.updated,
        try cache.add(alloc, "example.com"),
    );
    try testing.expect(
        try cache.contains(alloc, "example.com"),
    );

    // List
    var entries = try cache.list(alloc);
    deinitEntries(alloc, &entries);

    // Remove
    try cache.remove(alloc, "example.com");
    try testing.expect(
        !(try cache.contains(alloc, "example.com")),
    );
    try testing.expectEqual(
        AddResult.added,
        try cache.add(alloc, "example.com"),
    );
}

test isValidHost {
    const testing = std.testing;

    // Valid hostnames
    try testing.expect(isValidHost("localhost"));
    try testing.expect(isValidHost("example.com"));
    try testing.expect(isValidHost("sub.example.com"));

    // IPv4 addresses
    try testing.expect(isValidHost("127.0.0.1"));
    try testing.expect(isValidHost("192.168.1.1"));

    // IPv6 addresses
    try testing.expect(isValidHost("::1"));
    try testing.expect(isValidHost("2001:db8::1"));
    try testing.expect(isValidHost("2001:db8:0:1:1:1:1:1"));
    try testing.expect(!isValidHost("fe80::1%eth0")); // scopes not supported

    // Invalid hosts
    try testing.expect(!isValidHost(""));
    try testing.expect(!isValidHost("host\nname"));
    try testing.expect(!isValidHost(".example.com"));
    try testing.expect(!isValidHost("host..domain"));
    try testing.expect(!isValidHost("-hostname"));
    try testing.expect(!isValidHost("hostname-"));
    try testing.expect(!isValidHost("host name"));
    try testing.expect(!isValidHost("host_name"));
    try testing.expect(!isValidHost("host@domain"));
    try testing.expect(!isValidHost("host:port"));
}

test isValidUser {
    const testing = std.testing;

    // Valid
    try testing.expect(isValidUser("user"));
    try testing.expect(isValidUser("user-user"));
    try testing.expect(isValidUser("user_name"));
    try testing.expect(isValidUser("user.name"));
    try testing.expect(isValidUser("user123"));

    // Invalid
    try testing.expect(!isValidUser(""));
    try testing.expect(!isValidUser("user name"));
    try testing.expect(!isValidUser("user@example"));
    try testing.expect(!isValidUser("user:group"));
    try testing.expect(!isValidUser("user\nname"));
    try testing.expect(!isValidUser("a" ** 65)); // too long
}

test isValidCacheKey {
    const testing = std.testing;

    // Valid
    try testing.expect(isValidCacheKey("example.com"));
    try testing.expect(isValidCacheKey("sub.example.com"));
    try testing.expect(isValidCacheKey("192.168.1.1"));
    try testing.expect(isValidCacheKey("::1"));
    try testing.expect(isValidCacheKey("user@example.com"));
    try testing.expect(isValidCacheKey("user@192.168.1.1"));
    try testing.expect(isValidCacheKey("user@::1"));

    // Invalid
    try testing.expect(!isValidCacheKey(""));
    try testing.expect(!isValidCacheKey(".example.com"));
    try testing.expect(!isValidCacheKey("@example.com"));
    try testing.expect(!isValidCacheKey("user@"));
    try testing.expect(!isValidCacheKey("user@@example"));
    try testing.expect(!isValidCacheKey("user@.example.com"));
}
