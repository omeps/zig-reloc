const std = @import("std");
const builtin = @import("builtin");
const root = @import("zig_reloc_lib");
const Flag = enum { @"--help", @"-h", @"--namespace", @"-n", @"--output", @"-o", @"--checked", @"--formatted" };
var stdout_buf: [1024]u8 = undefined;
var stderr_buf: [1024]u8 = undefined;
pub fn main() !void {
    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    defer stdout.interface.flush() catch {};
    var stderr = std.fs.File.stderr().writer(&stderr_buf);
    defer stderr.interface.flush() catch {};

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
    var run_check = false;
    var run_format = false;
    var relocs: std.ArrayListUnmanaged(root.NamespaceRelocation) = .empty;
    defer relocs.deinit(allocator);
    while (args.next()) |arg| {
        if (std.meta.stringToEnum(Flag, arg)) |flag| switch (flag) {
            .@"-h", .@"--help" => {
                try stdout.interface.writeAll(
                    \\zig-reloc version 0.0.0: move declarations in a zig file and attempt to 
                    \\fix all references to said declerations.
                    \\
                    \\Usage: zig-reloc [FILE] [{{-n|--namespace} PREFIX NAME] ... [{-o|--output} FILE [--checked]]
                    \\If FILE is not provided, stdin will be used instead.
                    \\
                    \\ -n, --namespace        move all declarations with prefix PREFIX into a new  
                    \\                        namespace with name NAME
                    \\ -o, --output           print output to FILE instead of stdout
                    \\
                    \\ --checked              run `zig ast-check` on output after finishing. 
                    \\                        requires -o flag
                    \\By omeps
                    \\
                );
                return;
            },
            .@"-n", .@"--namespace" => {
                relocs.append(allocator, .{
                    .prefix = args.next() orelse {
                        stderr.interface.writeAll("too few args: -n requires 2 args, not 0") catch {};
                        return error.tooFewArgs;
                    },
                    .name = args.next() orelse {
                        stderr.interface.writeAll("too few args: -n requires 2 args, not 1") catch {};
                        return error.tooFewArgs;
                    },
                }) catch {
                    stderr.interface.writeAll("out of memory") catch {};

                    return error.outOfwMemory;
                };
            },
            .@"-o", .@"--output" => {
                if (out_file != null) {
                    stderr.interface.writeAll("too many output files: only 1 is allowed\n") catch {};
                    return error.doubledFiles;
                }
                out_file = args.next() orelse {
                    stderr.interface.writeAll("too few args: -o requires an output file arg\n") catch {};
                    return error.tooFewArgs;
                };
            },
            .@"--checked" => {
                run_check = true;
            },
            .@"--formatted" => {
                run_format = true;
        },
        } else {
            if (in_file != null) {
                stderr.interface.writeAll("too many output files: only 1 is allowed\n") catch {};
                return error.doubledFiles;
            }
            in_file = arg;
        }
    }

    _ = try root.run(arena.allocator(), allocator, if (in_file) |path| std.fs.cwd().openFile(path, .{}) catch |err| {
        stderr.interface.print("file open on {s} failed: {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    } else std.fs.File.stdin(), if (out_file) |path| std.fs.cwd().createFile(path, .{}) catch |err| {
        stderr.interface.print("file open on {s} failed: {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    } else std.fs.File.stdout(), relocs.items);
    if (run_check) {
        var checker = std.process.Child.init(&.{
            "zig",
            "ast-check",
            out_file orelse return error.CheckWithoutOutputFile,
        }, allocator);
        const result = try checker.spawnAndWait();
        switch (result) {
            inline .Unknown, .Signal, .Stopped => |term, tag| try stderr.interface.print("{t} result on zig ast-check call: {}\n", .{ tag, term }),
            .Exited => |code| if (code != 0) return error.CheckFail,
        }
    }
    if (run_format) {
        var checker = std.process.Child.init(&.{
            "zig",
            "fmt",
            out_file orelse return error.FmtWithoutOutputFile,
        }, allocator);
        const result = try checker.spawnAndWait();
        switch (result) {
            inline .Unknown, .Signal, .Stopped => |term, tag| try stderr.interface.print("{t} result on zig fmt call: {}\n", .{ tag, term }),
            .Exited => |code| if (code != 0) return error.formatFail,
        }
    }
}
