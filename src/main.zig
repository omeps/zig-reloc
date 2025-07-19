const std = @import("std");
const builtin = @import("builtin");
const root = @import("zig_reloc_lib");
const Flag = enum { @"--help", @"-h", @"--namespace", @"-n", @"--output", @"-o" };
pub fn main() !void {
    var timer: std.time.Timer = try .start();
    defer std.debug.print("time: {d}.{d:0>9}s\n", .{
        timer.read() / 1_000_000_000,
        timer.read() % 1_000_000_000,
    });
    var stdout = std.io.bufferedWriter(std.io.getStdOut().writer());
    defer stdout.flush() catch {};
    var stderr = std.io.bufferedWriter(std.io.getStdErr().writer());
    defer stderr.flush() catch {};

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (builtin.mode == .Debug) {
        _ = debug_allocator.deinit();
    };
    const allocator = if (builtin.mode == .Debug) debug_allocator.allocator() else std.heap.smp_allocator;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var args = std.process.ArgIterator.initWithAllocator(allocator) catch return 1;
    defer args.deinit();

    _ = args.skip();
    var in_file: ?[]const u8 = null;
    var out_file: ?[]const u8 = null;
    var relocs: std.ArrayListUnmanaged(root.NamespaceRelocation) = .empty;
    defer relocs.deinit(allocator);
    while (args.next()) |arg| {
        if (std.meta.stringToEnum(Flag, arg)) |flag| switch (flag) {
            .@"-h", .@"--help" => {
                try stdout.writer().writeAll(
                    \\zig-reloc version 0.0.0: move declarations in a zig file and attempt to 
                    \\fix all references to said declerations.
                    \\
                    \\Usage: zig-reloc [FILE] [{-n|--namespace} PREFIX NAME] ...
                    \\If FILE is not provided, stdin will be used instead.
                    \\
                    \\ -n, --namespace        move all declarations with prefix PREFIX into a new  
                    \\                        namespace with name NAME
                    \\By omeps
                    \\
                );
                return;
            },
            .@"-n", .@"--namespace" => {
                relocs.append(allocator, .{
                    .prefix = args.next() orelse {
                        stderr.writer().writeAll("too few args: -n requires 2 args, not 0") catch {};
                        return error.tooFewArgs;
                    },
                    .name = args.next() orelse {
                        stderr.writer().writeAll("too few args: -n requires 2 args, not 1") catch {};
                        return error.tooFewArgs;
                    },
                }) catch {
                    stderr.writer().writeAll("out of memory") catch {};

                    return error.outOfwMemory;
                };
            },
            .@"-o", .@"--output" => {
                out_file = args.next() orelse {
                    stderr.writer().writeAll("too few args: -o requires an output file arg\n") catch {};
                    return error.tooFewArgs;
                };
            },
        } else {
            in_file = arg;
        }
    }

    _ = try root.run(arena.allocator(), allocator, if (in_file) |path| std.fs.cwd().openFile(path, .{}) catch |err| {
        std.fmt.format(stderr.writer().any(), "file open on {s} failed: {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    } else std.io.getStdIn(), if (out_file) |path| std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch |err| {
        std.fmt.format(stderr.writer().any(), "file open on {s} failed: {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    } else std.io.getStdOut(), relocs.items);
}
