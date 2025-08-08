const std = @import("std");
const builtin = @import("builtin");
const root = @import("zig_reloc_lib");
const Flag = enum {
    @"--help",
    @"-h",
    @"--namespace",
    @"-n",
    @"--output",
    @"-o",
    @"--checked",
    @"--formatted",
    @"--styled",
};
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
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var run_check = false;
    var run_format = false;
    var style: root.Style = .none;
    var relocs: std.ArrayListUnmanaged(root.NamespaceRelocation) = .empty;
    defer relocs.deinit(allocator);
    while (args.next()) |arg| {
        if (std.meta.stringToEnum(Flag, arg)) |flag| switch (flag) {
            .@"-h", .@"--help" => {
                try stdout.interface.writeAll(
                    \\zig-reloc version 0.0.1: move declarations in a zig file and attempt to fix
                    \\all references to said declarations.
                    \\
                    \\Usage: zig-reloc [FILE] [{{-n|--namespace} PREFIX NAME] ... [{-o|--output} FILE [--checked] [--formatted]] [--styled]
                    \\If FILE is not provided, stdin will be used instead.
                    \\
                    \\ -n, --namespace        move all declarations with prefix PREFIX into a new  
                    \\                        namespace with name NAME
                    \\ -o, --output           print output to FILE instead of stdout
                    \\
                    \\ --checked              run system `zig ast-check` on output after finishing. 
                    \\                        requires -o flag
                    \\ --formatted            run system `zig fmt` on output after finishing. 
                    \\                        requires -o flag
                    \\ --styled               make all moved declarations styled as described in
                    \\                        https://ziglang.org/documentation/master/#Names.
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
                if (out_path != null) {
                    stderr.interface.writeAll("too many output files: only 1 is allowed\n") catch {};
                    return error.doubledFiles;
                }
                out_path = args.next() orelse {
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
            .@"--styled" => {
                style = .zig;
            },
        } else {
            if (in_path != null) {
                stderr.interface.writeAll("too many output files: only 1 is allowed\n") catch {};
                return error.doubledFiles;
            }
            in_path = arg;
        }
    }
    const input = if (in_path) |path| std.fs.cwd().openFile(path, .{}) catch |err| {
        stderr.interface.print("file open on {s} failed: {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    } else std.fs.File.stdin();
    defer input.close();
    const known_file_size = if (input.stat()) |stat| stat.size + 1 else |_| 0;
    var file_buffer_writer: std.io.Writer.Allocating = try .initCapacity(allocator, known_file_size);
    defer file_buffer_writer.deinit();
    var in_buf: [1024]u8 = undefined;
    var reader = input.readerStreaming(&.{});
    while (true) {
        const read_len = reader.read(&in_buf) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        try file_buffer_writer.writer.writeAll(in_buf[0..read_len]);
    }
    _ = try file_buffer_writer.writer.sendFileAll(&reader, .unlimited);
    var file_buffer = file_buffer_writer.toArrayList();
    defer file_buffer.deinit(allocator);
    if (file_buffer.items.len == 0 or file_buffer.items[file_buffer.items.len - 1] != 0) try file_buffer.append(allocator, 0);
    var ast: std.zig.Ast = try .parse(allocator, file_buffer.items[0 .. file_buffer.items.len - 1 :0], .zig);
    defer ast.deinit(allocator);
    const out_file: std.fs.File = if (out_path) |path| std.fs.cwd().createFile(path, .{}) catch |err| {
        stderr.interface.print("file open on {s} failed: {s}\n", .{ path, @errorName(err) }) catch {};
        return err;
    } else std.fs.File.stdout();
    var out_buffer: [4096]u8 = undefined;
    var out_writer = out_file.writerStreaming(&out_buffer);

    _ = try root.run(arena.allocator(), allocator, ast, &out_writer.interface, relocs.items, style);
    if (run_check) {
        var checker = std.process.Child.init(&.{
            "zig",
            "ast-check",
            out_path orelse return error.CheckWithoutOutputFile,
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
            out_path orelse return error.FmtWithoutOutputFile,
        }, allocator);
        const result = try checker.spawnAndWait();
        switch (result) {
            inline .Unknown, .Signal, .Stopped => |term, tag| try stderr.interface.print("{t} result on zig fmt call: {}\n", .{ tag, term }),
            .Exited => |code| if (code != 0) return error.formatFail,
        }
    }
}
