const std = @import("std");
const Ast = std.zig.Ast;
fn sliceTo(start: [*]const u8, end: [*]const u8) []const u8 {
    return start[0 .. end - start];
}
fn tokenSource(tree: Ast, token_index: Ast.TokenIndex) []const u8 {
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = tree.tokenStart(token_index),
    };
    const token = tokenizer.next();
    return tree.source[token.loc.start..token.loc.end];
}
const findFlag = struct {
    fn cmp(_: void, a: findFlag, b: findFlag) bool {
        return std.sort.asc(usize)({}, a.index, b.index);
    }
    index: usize,
    flag_type: enum {
        start,
        end,
    },
};
const Update = struct {
    original: []const u8,
    replace: []const u8,
    pub fn cmp(_: void, a: Update, b: Update) bool {
        return std.sort.asc(usize)({}, @intFromPtr(a.original.ptr), @intFromPtr(b.original.ptr));
    }
};
pub const Case = enum {
    camel,
    pascal,
    snake,
    upper_snake,
    const Iterator = struct {
        case: Case,
        buf: []const u8,
        pub fn next(self: *Iterator) ?[]const u8 {
            if (self.buf.len == 0) return null;
            var i: usize = 1;
            while (i < self.buf.len and switch (self.case) {
                .pascal, .camel => (self.buf[i] < 'A' or 'Z' < self.buf[i]),
                .snake, .upper_snake => self.buf[i] != '_',
            }) {
                i += 1;
            }
            defer self.buf = self.buf[i..];
            const start: u1 = if (self.case == .snake or self.case == .upper_snake) if (self.buf[0] == '_') 1 else 0 else 0;
            return self.buf[start..i];
        }
    };
    pub fn determine(decl: Declaration.ParentedValue) Case {
        return switch (decl.value) {
            .func => .camel,
            .composed_type => .pascal,
            .typeof_shortcut => .snake,
            .equals_shortcut => determine((decl.takeShortcut() orelse return .pascal).*),
            .leaf => .snake,
            .type => .pascal,
        };
    }
    pub fn change(original: []const u8, new_case: Case, arena: std.mem.Allocator) error{OutOfMemory}![]const u8 {
        var case_discrimination: enum {
            any,
            caps,
            lowers,
        } = .any;
        const original_case: Case = determine_case: {
            for (original) |char| {
                switch (case_discrimination) {
                    .any => {
                        switch (char) {
                            'a'...'z' => case_discrimination = .lowers,
                            'A'...'Z' => case_discrimination = .caps,
                            else => case_discrimination = .any,
                        }
                    },
                    .caps => {
                        switch (char) {
                            'a'...'z' => break :determine_case .pascal,
                            '_' => break :determine_case .upper_snake,
                            else => {},
                        }
                    },
                    .lowers => {
                        switch (char) {
                            'A'...'Z' => break :determine_case .camel,
                            '_' => break :determine_case .snake,
                            else => {},
                        }
                    },
                }
            }
            if (case_discrimination == .lowers) break :determine_case .snake;
            if (case_discrimination == .caps) break :determine_case .upper_snake;
            return original;
        };
        if (original_case == new_case) return original;

        var words: Iterator = .{ .case = original_case, .buf = original };
        var total_len: usize = 0;
        total_len += words.next().?.len;
        while (words.next()) |word| {
            total_len += word.len;
            if (new_case == .snake or new_case == .upper_snake) total_len += 1;
        }
        const output = try arena.alloc(u8, total_len);
        words = .{ .case = original_case, .buf = original };
        var out_write = std.io.Writer.fixed(output);
        {
            const first_word = words.next().?;
            const out_slice = out_write.writableSlice(first_word.len) catch unreachable;
            switch (new_case) {
                .camel, .snake => for (first_word, out_slice) |i, *o| {
                    o.* = std.ascii.toLower(i);
                },
                .upper_snake => for (first_word, out_slice) |i, *o| {
                    o.* = std.ascii.toUpper(i);
                },
                .pascal => if (first_word.len > 0) {
                    out_slice[0] = std.ascii.toUpper(first_word[0]);
                    for (first_word[1..], out_slice[1..]) |i, *o| {
                        o.* = std.ascii.toLower(i);
                    }
                },
            }
        }
        while (words.next()) |word| {
            if (new_case == .snake or new_case == .upper_snake) out_write.writeByte('_') catch unreachable;
            const out_slice = out_write.writableSlice(word.len) catch unreachable;
            switch (new_case) {
                .snake => for (word, out_slice) |i, *o| {
                    o.* = std.ascii.toLower(i);
                },
                .upper_snake => for (word, out_slice) |i, *o| {
                    o.* = std.ascii.toUpper(i);
                },
                .camel, .pascal => if (word.len > 0) {
                    out_slice[0] = std.ascii.toUpper(word[0]);
                    for (word[1..], out_slice[1..]) |i, *o| {
                        o.* = std.ascii.toLower(i);
                    }
                },
            }
        }
        return output;
    }
};
test "upper_snake_case" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("SNAKE_CASE_OUTPUT", try Case.change("snake_case_output", .upper_snake, arena.allocator()));
    try std.testing.expectEqualStrings("SNAKE_CASE_OUTPUT", try Case.change("SNAKE_CASE_OUTPUT", .upper_snake, arena.allocator()));
    try std.testing.expectEqualStrings("SNAKE_CASE_OUTPUT", try Case.change("SnakeCaseOutput", .upper_snake, arena.allocator()));
    try std.testing.expectEqualStrings("SNAKE_CASE_OUTPUT", try Case.change("snakeCaseOutput", .upper_snake, arena.allocator()));
}
test "pascal_case" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("PascalCaseOutput", try Case.change("pascal_case_output", .pascal, arena.allocator()));
    try std.testing.expectEqualStrings("PascalCaseOutput", try Case.change("PASCAL_CASE_OUTPUT", .pascal, arena.allocator()));
    try std.testing.expectEqualStrings("PascalCaseOutput", try Case.change("PascalCaseOutput", .pascal, arena.allocator()));
    try std.testing.expectEqualStrings("PascalCaseOutput", try Case.change("pascalCaseOutput", .pascal, arena.allocator()));
}
test "snake_case" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("snake_case_output", try Case.change("snake_case_output", .snake, arena.allocator()));
    try std.testing.expectEqualStrings("snake_case_output", try Case.change("SNAKE_CASE_OUTPUT", .snake, arena.allocator()));
    try std.testing.expectEqualStrings("snake_case_output", try Case.change("SnakeCaseOutput", .snake, arena.allocator()));
    try std.testing.expectEqualStrings("snake_case_output", try Case.change("snakeCaseOutput", .snake, arena.allocator()));
}
test "camel_case" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("camelCaseOutput", try Case.change("camel_case_output", .camel, arena.allocator()));
    try std.testing.expectEqualStrings("camelCaseOutput", try Case.change("CAMEL_CASE_OUTPUT", .camel, arena.allocator()));
    try std.testing.expectEqualStrings("camelCaseOutput", try Case.change("CamelCaseOutput", .camel, arena.allocator()));
    try std.testing.expectEqualStrings("camelCaseOutput", try Case.change("camelCaseOutput", .camel, arena.allocator()));
}
fn unraw(identifier: []const u8) []const u8 {
    if (identifier.len > 0 and identifier[0] == '@') {
        return identifier[2 .. identifier.len - 1];
    } else {
        return identifier;
    }
}
pub const Declaration = struct {
    const Value = union(enum) {
        composed_type: []Declaration,
        typeof_shortcut: []const []const u8,
        equals_shortcut: []const []const u8,
        leaf,
        type,
        func,
        pub fn sort_by_name(self: Value) void {
            if (self == .composed_type) {
                const decls = self.composed_type;
                std.mem.sortUnstable(Declaration, decls, {}, cmp_names);
                for (decls) |*decl| {
                    decl.value.value.sort_by_name();
                }
            }
        }
        pub fn sort_by_node(self: Value, ast: Ast) void {
            if (self == .composed_type) {
                const decls = self.composed_type;
                std.mem.sortUnstable(Declaration, decls, ast, cmp_nodes);
            }
        }
        pub fn findChildDecl(scope: Declaration.Value, string: []const u8) ?*const Declaration.ParentedValue {
            if (scope != .composed_type) return null;
            return &scope.composed_type[std.sort.binarySearch(Declaration, scope.composed_type, string, order_name) orelse return null].value;
        }
    };
    const ParentedValue = struct {
        value: Value,
        parent: ?*const ParentedValue = null,
        pub fn findDecl(scope: Declaration.ParentedValue, string: []const u8) ?*const Declaration.ParentedValue {
            return scope.value.findChildDecl(string) orelse (scope.parent orelse return null).findDecl(string);
        }
        pub fn takeShortcut(decl: Declaration.ParentedValue) ?*const Declaration.ParentedValue {
            const path = switch (decl.value) {
                .typeof_shortcut, .equals_shortcut => |x| x,
                else => return null,
            };
            if (path.len == 0) return null;
            const parent = decl.parent orelse return null;
            var access = parent.findDecl(path[0]) orelse return null;
            for (path[1..]) |segment| {
                access = access.value.findChildDecl(segment) orelse return null;
            }
            return access;
        }
        pub fn reset_parents(self: *const ParentedValue) void {
            if (self.value == .composed_type) {
                for (self.value.composed_type) |*child| {
                    child.value.parent = self;
                    child.value.reset_parents();
                }
            }
        }
    };
    name: []const u8,
    node: Ast.Node.Index,
    value: ParentedValue,
    pub fn order_name(str: []const u8, decl: Declaration) std.math.Order {
        return std.mem.order(u8, str, decl.name);
    }
    pub fn cmp_names(_: void, a: Declaration, b: Declaration) bool {
        return std.mem.lessThan(u8, a.name, b.name);
    }
    pub fn cmp_nodes(ast: Ast, a: Declaration, b: Declaration) bool {
        return std.sort.asc(usize)(
            {},
            @intFromPtr(ast.getNodeSource(a.node).ptr),
            @intFromPtr(ast.getNodeSource(b.node).ptr),
        );
    }
};
pub const AccessIterator = struct {
    ast: Ast,
    current_decl: Declaration,
};
pub const NamespaceRelocation = struct {
    prefix: []const u8,
    name: []const u8,
};
const RelocMap = std.AutoHashMapUnmanaged(*const Declaration.Value, NamespaceRelocation);
pub const Style = enum {
    zig,
    none,
};
const SearchContext = struct {
    ast: Ast,
    decls: RelocMap,
    updates: *std.ArrayList(Update),
    styling: Style,
    arena: std.mem.Allocator,

    pub fn search(context: SearchContext, node: Ast.Node.Index, scope: Declaration.ParentedValue) !?*const Declaration.ParentedValue {
        var relevant_decl: ?*const Declaration.ParentedValue = switch (context.ast.nodeTag(node)) {
            .@"errdefer",
            .test_decl,
            => {
                _ = try context.search(
                    context.ast.nodeData(node).opt_token_and_node.@"1",
                    scope,
                );
                return null;
            },
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const decl_nodes = context.ast.fullVarDecl(node).?.ast;
                const inner_scope = if (scope.findDecl(context.ast.tokenSlice(decl_nodes.mut_token + 1))) |inner| inner.* else scope;
                if (decl_nodes.type_node.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                if (decl_nodes.align_node.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                if (decl_nodes.addrspace_node.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                if (decl_nodes.section_node.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                if (decl_nodes.init_node.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                return null;
            },
            .root => {
                for (context.ast.rootDecls()) |d| {
                    _ = try context.search(
                        d,
                        scope,
                    );
                }
                return null;
            },
            .@"defer" => {
                _ = try context.search(
                    context.ast.nodeData(node).node,
                    scope,
                );
                return null;
            },
            .@"catch" => {
                const lhs, const rhs = context.ast.nodeData(node).node_and_node;
                const left = try context.search(
                    lhs,
                    scope,
                );
                const right = try context.search(
                    rhs,
                    scope,
                );
                return left orelse right;
            },
            .identifier => scope.findDecl(unraw(context.ast.tokenSlice(context.ast.nodeMainToken(node)))) orelse return null,
            .field_access => access: {
                const lhs, const a = context.ast.nodeData(node).node_and_token;
                break :access (try context.search(
                    lhs,
                    scope,
                ) orelse return null).value.findChildDecl(context.ast.tokenSlice(a));
            },
            .fn_decl => {
                const proto, const block = context.ast.nodeData(node).node_and_node;
                _ = try context.search(
                    block,
                    scope,
                );
                return try context.search(
                    proto,
                    scope,
                );
            },
            .fn_proto,
            .fn_proto_one,
            .fn_proto_multi,
            .fn_proto_simple,
            => {
                var buf: [1]Ast.Node.Index = undefined;
                const data = (context.ast.fullFnProto(&buf, node) orelse return null).ast;
                for (data.params) |p| _ = try context.search(
                    p,
                    scope,
                );
                if (data.align_expr.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                if (data.return_type.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                if (data.addrspace_expr.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                if (data.section_expr.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                if (data.callconv_expr.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                return null;
            },
            .block,
            .block_two,
            .block_semicolon,
            .block_two_semicolon,
            => {
                var buf: [2]Ast.Node.Index = undefined;
                for (context.ast.blockStatements(&buf, node) orelse return null) |statement| {
                    _ = try context.search(
                        statement,
                        scope,
                    );
                }
                return null;
            },
            .container_decl,
            .container_decl_two,
            .container_decl_arg,
            .container_decl_trailing,
            .container_decl_two_trailing,
            .container_decl_arg_trailing,
            => {
                var buf: [2]Ast.Node.Index = undefined;
                const full = (context.ast.fullContainerDecl(&buf, node) orelse return null).ast;
                for (full.members) |member| {
                    _ = try context.search(
                        member,
                        scope,
                    );
                }
                return null;
            },
            .container_field,
            .container_field_init,
            .container_field_align,
            => {
                const full = (context.ast.fullContainerField(node) orelse return null).ast;
                const inner_scope = if (scope.findDecl(context.ast.tokenSlice(full.main_token))) |inner| inner.* else scope;
                if (full.align_expr.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                if (full.type_expr.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                if (full.value_expr.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    inner_scope,
                );
                return null;
            },
            .array_init,
            .array_init_one,
            .array_init_dot,
            .array_init_comma,
            .array_init_dot_two,
            .array_init_one_comma,
            .array_init_dot_two_comma,
            .array_init_dot_comma,
            => {
                var buf: [2]Ast.Node.Index = undefined;
                const full = (context.ast.fullArrayInit(&buf, node) orelse return null).ast;
                for (full.elements) |element| {
                    _ = try context.search(
                        element,
                        scope,
                    );
                }
                if (full.type_expr.unwrap()) |sub_node| {
                    _ = try context.search(
                        sub_node,
                        scope,
                    );
                }
                return null;
            },
            .optional_type => {
                _ = try context.search(
                    context.ast.nodeData(node).node,
                    scope,
                );
                return null;
            },
            .ptr_type,
            .ptr_type_aligned,
            .ptr_type_sentinel,
            .ptr_type_bit_range,
            => {
                const full = (context.ast.fullPtrType(node) orelse return null).ast;
                if (full.align_node.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                if (full.addrspace_node.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                if (full.sentinel.unwrap()) |sub_node| _ = try context.search(
                    sub_node,
                    scope,
                );
                _ = try context.search(
                    full.child_type,
                    scope,
                );
                return null;
            },
            .assign_mul,
            .assign_div,
            .assign_mod,
            .assign_add,
            .assign_sub,
            .assign_shl,
            .assign_shr,
            .assign_bit_or,
            .assign_shl_sat,
            .assign_bit_and,
            .assign_bit_xor,
            .assign_mul_sat,
            .assign_add_sat,
            .assign_sub_sat,
            .assign_mul_wrap,
            .assign_add_wrap,
            .assign_sub_wrap,
            .assign,
            .bit_or,
            .bit_and,
            .bit_xor,
            .@"orelse",
            .bool_or,
            .bool_and,
            .bang_equal,
            .equal_equal,
            .less_than,
            .less_or_equal,
            .greater_or_equal,
            .greater_than,
            .mul,
            .mul_sat,
            .mul_wrap,
            .div,
            .add,
            .add_sat,
            .add_wrap,
            .sub,
            .sub_wrap,
            .sub_sat,
            .shl,
            .shl_sat,
            .shr,
            .mod,
            .array_cat,
            .array_mult,
            => {
                const lhs, const rhs = context.ast.nodeData(node).node_and_node;
                _ = try context.search(
                    lhs,
                    scope,
                );
                _ = try context.search(
                    rhs,
                    scope,
                );
                return null;
            },
            .struct_init_one,
            .struct_init_dot,
            .struct_init,
            .struct_init_comma,
            .struct_init_dot_two,
            .struct_init_one_comma,
            .struct_init_dot_comma,
            .struct_init_dot_two_comma,
            => {
                var buf: [2]Ast.Node.Index = undefined;
                const full = context.ast.fullStructInit(&buf, node) orelse return null;
                for (full.ast.fields) |field| _ = try context.search(
                    field,
                    scope,
                );
                if (full.ast.type_expr.unwrap()) |ty| return try context.search(
                    ty,
                    scope,
                );
                return null;
            },
            .@"switch", .switch_comma => {
                const full = context.ast.fullSwitch(node) orelse return null;
                _ = try context.search(
                    full.ast.condition,
                    scope,
                );
                for (full.ast.cases) |case|
                    _ = try context.search(
                        case,
                        scope,
                    );
                return null;
            },
            .@"try",
            .@"comptime",
            .negation,
            .negation_wrap,
            .address_of,
            .deref,
            .bool_not,
            .bit_not,
            => {
                return try context.search(
                    context.ast.nodeData(node).node,
                    scope,
                );
            },
            .array_type, .array_type_sentinel => {
                const full = context.ast.fullArrayType(node) orelse return null;
                _ = try context.search(
                    full.ast.elem_type,
                    scope,
                );
                _ = try context.search(
                    full.ast.elem_count,
                    scope,
                );
                if (full.ast.sentinel.unwrap()) |sentinel|
                    _ = try context.search(
                        sentinel,
                        scope,
                    );
                return null;
            },
            .builtin_call, .builtin_call_two, .builtin_call_comma, .builtin_call_two_comma => {
                var buffer: [2]Ast.Node.Index = undefined;
                const params = context.ast.builtinCallParams(&buffer, node) orelse return null;
                for (params) |param| _ = try context.search(
                    param,
                    scope,
                );
                return null;
            },
            else => return null,
            .slice, .slice_open, .slice_sentinel => {
                const slice = context.ast.fullSlice(node) orelse return null;
                _ = try context.search(
                    slice.ast.sliced,
                    scope,
                );
                _ = try context.search(
                    slice.ast.start,
                    scope,
                );
                if (slice.ast.end.unwrap()) |end| _ = try context.search(
                    end,
                    scope,
                );
                if (slice.ast.sentinel.unwrap()) |sentinel| _ = try context.search(
                    sentinel,
                    scope,
                );
                return null;
            },
            .call, .call_one, .call_comma, .call_one_comma => {
                var buf: [1]Ast.Node.Index = undefined;
                const full = context.ast.fullCall(&buf, node) orelse return null;
                for (full.ast.params) |param| _ = try context.search(
                    param,
                    scope,
                );
                _ = try context.search(
                    full.ast.fn_expr,
                    scope,
                );
                return null;
            },
            .@"return" => {
                if (context.ast.nodeData(node).opt_node.unwrap()) |return_value| _ = try context.search(
                    return_value,
                    scope,
                );
                return null;
            },
            .grouped_expression, .unwrap_optional => {
                _ = try context.search(
                    context.ast.nodeData(node).node_and_token.@"0",
                    scope,
                );
                return null;
            },
            .switch_case_one, .switch_case, .switch_case_inline, .switch_case_inline_one => {
                const full = context.ast.fullSwitchCase(node) orelse return null;
                for (full.ast.values) |value| _ = try context.search(
                    value,
                    scope,
                );
                return try context.search(
                    full.ast.target_expr,
                    scope,
                );
            },
            .switch_range => {
                const lhs, const rhs = context.ast.nodeData(node).node_and_node;
                _ = try context.search(
                    lhs,
                    scope,
                );
                _ = try context.search(
                    rhs,
                    scope,
                );
                return null;
            },
            .@"continue", .@"break" => {
                _, const result = context.ast.nodeData(node).opt_token_and_opt_node;
                if (result.unwrap()) |result_node| _ = try context.search(
                    result_node,
                    scope,
                );
                return null;
            },
            .@"while", .while_cont, .while_simple => {
                const full = context.ast.fullWhile(node) orelse return null;
                _ = try context.search(
                    full.ast.cond_expr,
                    scope,
                );
                _ = try context.search(
                    full.ast.then_expr,
                    scope,
                );
                if (full.ast.cont_expr.unwrap()) |cont_node| _ = try context.search(
                    cont_node,
                    scope,
                );
                if (full.ast.else_expr.unwrap()) |else_node| _ = try context.search(
                    else_node,
                    scope,
                );
                return null;
            },
            .for_range, .for_simple, .@"for" => {
                const full = context.ast.fullFor(node) orelse return null;
                if (full.ast.else_expr.unwrap()) |else_node| _ = try context.search(
                    else_node,
                    scope,
                );
                for (full.ast.inputs) |input| _ = try context.search(
                    input,
                    scope,
                );
                _ = try context.search(
                    full.ast.then_expr,
                    scope,
                );
                return null;
            },
            .@"if", .if_simple => {
                const full = context.ast.fullIf(node) orelse return null;
                if (full.ast.else_expr.unwrap()) |else_node| _ = try context.search(
                    else_node,
                    scope,
                );
                _ = try context.search(
                    full.ast.cond_expr,
                    scope,
                );
                _ = try context.search(
                    full.ast.then_expr,
                    scope,
                );
                return null;
            },
            .array_access => {
                const lhs, const rhs = context.ast.nodeData(node).node_and_node;
                _ = try context.search(
                    lhs,
                    scope,
                );
                _ = try context.search(
                    rhs,
                    scope,
                );
                return null;
            },
        };

        if (relevant_decl) |d| if (context.decls.get(&d.value)) |reloc| {
            const access_slice = switch (context.ast.nodeTag(node)) {
                .field_access => context.ast.tokenSlice(context.ast.nodeData(node).node_and_token.@"1"),
                //FIX for raw IDs later
                .identifier => context.ast.tokenSlice(context.ast.nodeMainToken(node)),
                else => null,
            };
            if (access_slice) |s| {
                try context.updates.appendSlice(switch (context.styling) {
                    .zig => &[_]Update{
                        .{
                            .original = s[0..reloc.prefix.len],
                            .replace = reloc.name,
                        },
                        .{
                            .original = s[reloc.prefix.len..reloc.prefix.len],
                            .replace = ".",
                        },
                        .{
                            .original = s[reloc.prefix.len..],
                            .replace = try Case.change(s[reloc.prefix.len..], .determine(d.*), context.arena),
                        },
                    },
                    .none => &[_]Update{
                        .{
                            .original = s[0..reloc.prefix.len],
                            .replace = reloc.name,
                        },
                        .{
                            .original = s[reloc.prefix.len..reloc.prefix.len],
                            .replace = ".",
                        },
                    },
                });
            }
        };
        var canary = relevant_decl;
        while (relevant_decl) |d| {
            if (d.value == .typeof_shortcut or d.value == .equals_shortcut) {
                relevant_decl = d.takeShortcut();
                canary = if (relevant_decl) |post| post.takeShortcut() else null;
                if (canary orelse continue == d) break;
            } else break;
        }
        return relevant_decl;
    }
};
pub fn prettyprint(writer: *std.io.Writer, tree: Declaration, depth: usize) !void {
    if (depth > 0) {
        try writer.splatByteAll(' ', depth -% 1);
        try writer.writeAll("└");
    }
    try writer.writeAll(tree.name);
    switch (tree.value.value) {
        .composed_type => |decls| {
            _ = try writer.writeByte('\n');
            for (decls) |decl| {
                try prettyprint(writer, decl, depth + 1);
            }
        },
        .typeof_shortcut, .equals_shortcut => |fields| {
            try writer.writeAll(" -> ");
            try writer.writeAll(fields[0]);
            for (fields[1..]) |field| {
                try writer.writeByte('.');
                try writer.writeAll(field);
            }
            try writer.writeByte('\n');
        },
        .leaf => try writer.writeByte('\n'),
        .type => try writer.writeByte('\n'),
        .func => try writer.writeByte('\n'),
    }
}
var update_index: usize = 0;
fn outputUpdated(writer: *std.io.Writer, source: []const u8, updates: []Update) !void {
    var range = source;
    while (update_index < updates.len) : (update_index += 1) {
        const i = updates[update_index];
        if (@intFromPtr(i.original.ptr) >= @intFromPtr(range.ptr + range.len)) {
            break;
        }
        if (@intFromPtr(range.ptr) <= @intFromPtr(i.original.ptr) and @intFromPtr(i.original.ptr[i.original.len..]) <= @intFromPtr(range.ptr[range.len..])) {
            const equal_range = range[0 .. i.original.ptr - range.ptr];
            try writer.writeAll(equal_range);
            try writer.writeAll(i.replace);
            range = i.original.ptr[i.original.len .. (range.ptr + range.len) - i.original.ptr];
        }
    }
    try writer.writeAll(range);
}
pub fn run(arena: std.mem.Allocator, gpa: std.mem.Allocator, input: std.fs.File, output_writer: *std.io.Writer, relocs: []const NamespaceRelocation, styling: Style) !void {
    var updates: std.ArrayList(Update) = .init(gpa);
    defer updates.deinit();
    update_index = 0;
    const known_file_size = if (input.stat()) |stat| stat.size + 1 else |_| 0;
    var file_buffer_writer: std.io.Writer.Allocating = try .initCapacity(gpa, known_file_size);
    defer file_buffer_writer.deinit();
    var in_buf: [1024]u8 = undefined;
    var reader = input.reader(&.{});
    while (true) {
        const read_len = reader.read(&in_buf) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        try file_buffer_writer.writer.writeAll(in_buf[0..read_len]);
    }
    _ = try file_buffer_writer.writer.sendFileAll(&reader, .unlimited);
    var file_buffer = file_buffer_writer.toArrayList();
    defer file_buffer.deinit(gpa);
    if (file_buffer.items.len == 0 or file_buffer.items[file_buffer.items.len - 1] != 0) try file_buffer.append(gpa, 0);
    var ast: Ast = try .parse(gpa, file_buffer.items[0 .. file_buffer.items.len - 1 :0], .zig);
    defer ast.deinit(gpa);
    const output = try arena.create(Declaration.ParentedValue); //since this is on the arena no need to errdefer free
    output.* = .{ .value = try getContainerDecl(ast, ast.rootDecls(), arena) };
    output.value.sort_by_name();
    output.reset_parents();
    var decls: RelocMap = .empty;
    defer decls.deinit(gpa);
    for (0..output.value.composed_type.len) |i| get_reloc: for (relocs) |r| if (std.mem.startsWith(u8, output.value.composed_type[i].name, r.prefix)) {
        try decls.put(gpa, &output.value.composed_type[i].value.value, r);
        if (output.value.composed_type[i].value.value != .func or ast.nodeTag(output.value.composed_type[i].node) == .fn_decl) {
            try updates.append(.{
                .original = output.value.composed_type[i].name[0..r.prefix.len],
                .replace = "@\"",
            });
            if (styling == .zig)
                try updates.append(.{
                    .original = output.value.composed_type[i].name[r.prefix.len..],
                    .replace = try Case.change(output.value.composed_type[i].name[r.prefix.len..], .determine(output.value.composed_type[i].value), arena),
                });
            try updates.append(.{
                .original = output.value.composed_type[i].name[output.value.composed_type[i].name.len..output.value.composed_type[i].name.len],
                .replace = "\"",
            });
        }
        break :get_reloc;
    };

    _ = try SearchContext.search(
        .{
            .ast = ast,
            .decls = decls,
            .updates = &updates,
            .styling = styling,
            .arena = arena,
        },
        .root,
        output.*,
    );

    std.mem.sort(Update, updates.items, {}, Update.cmp);
    output.value.sort_by_node(ast);

    {
        const namespaces = try arena.alloc(std.io.Writer.Allocating, relocs.len);
        defer for (namespaces) |*namespace| namespace.deinit();
        for (namespaces) |*namespace| {
            namespace.* = .init(gpa);
        }
        const outs = output.value.composed_type;
        for (0..outs.len) |i| get_reloc: {
            const decl = outs[i];
            for (namespaces, relocs) |*n, r| if (std.mem.startsWith(u8, decl.name, r.prefix)) {
                const writer = &n.writer;

                defer writer.flush() catch {};
                switch (ast.nodeTag(decl.node)) {
                    .fn_proto_simple, .fn_proto, .fn_proto_one, .fn_proto_multi => {
                        var buf: [1]Ast.Node.Index = undefined;
                        const full = ast.fullFnProto(&buf, decl.node).?;
                        if (full.extern_export_inline_token != null and std.mem.eql(u8, ast.tokenSlice(full.extern_export_inline_token.?), "extern")) {
                            try writer.print(
                                \\pub const @"{s}" = @extern(*const fn
                            , .{switch (styling) {
                                .zig => try Case.change(ast.tokenSlice(full.name_token.?)[r.prefix.len..], .camel, arena),
                                .none => ast.tokenSlice(full.name_token.?)[r.prefix.len..],
                            }});
                            if (full.ast.callconv_expr.unwrap() != null) {
                                const proto_start = tokenSource(ast, full.ast.fn_token + 2);
                                const proto_end = ast.getNodeSource(full.ast.return_type.unwrap().?);
                                const proto = proto_start.ptr[0 .. proto_end.ptr - proto_start.ptr + proto_end.len];
                                try outputUpdated(writer, proto, updates.items);
                            } else {
                                const proto_start = tokenSource(ast, full.ast.fn_token + 2);
                                const proto_end = ast.getNodeSource(full.ast.return_type.unwrap().?);
                                const proto = proto_start.ptr[0 .. proto_end.ptr - proto_start.ptr];
                                try outputUpdated(writer, proto, updates.items);
                                try writer.writeAll(" callconv(.C) ");
                                try outputUpdated(writer, proto_end, updates.items);
                            }
                            try writer.print(
                                \\, .{{
                                \\  .name = "{s}",
                                \\
                            , .{ast.tokenSlice(full.name_token.?)});
                            if (full.lib_name) |lib| {
                                try writer.print(
                                    \\  .lib_name = {s},
                                    \\
                                , .{ast.tokenSlice(lib)});
                            }
                            try writer.print(
                                \\}});
                                \\
                            , .{});
                        } else {
                            try outputUpdated(writer, ast.getNodeSource(decl.node), updates.items);
                        }
                    },
                    else => {
                        try outputUpdated(writer, sliceTo(ast.getNodeSource(decl.node).ptr, if (i + 1 < outs.len)
                            ast.getNodeSource(outs[i + 1].node).ptr
                        else
                            ast.source.ptr[ast.source.len..]), updates.items);
                    },
                }
                break :get_reloc;
            };
            try outputUpdated(output_writer, sliceTo(ast.getNodeSource(decl.node).ptr, if (i + 1 < outs.len)
                ast.getNodeSource(outs[i + 1].node).ptr
            else
                ast.source.ptr[ast.source.len..]), updates.items);
        }
        var last_namespace: ?[]const u8 = null;
        for (namespaces, relocs) |*namespace, reloc| {
            if (last_namespace != null and !std.mem.eql(u8, last_namespace.?, reloc.name)) {
                try output_writer.writeAll("};\n");
            }
            if (last_namespace != null and std.mem.eql(u8, last_namespace.?, reloc.name)) {
                try output_writer.writeAll(namespace.getWritten());
            } else {
                try output_writer.print("pub const {s} = struct {{\n", .{reloc.name});
                try output_writer.writeAll(namespace.getWritten());
            }
            last_namespace = reloc.name;
        }
        if (last_namespace != null) try output_writer.writeAll("};\n");
        try output_writer.flush();
    }
}
fn getContainerDecl(ast: Ast, decls: []const Ast.Node.Index, arena: std.mem.Allocator) std.mem.Allocator.Error!Declaration.Value {
    var decl_count: usize = 0;
    for (decls) |decl_node_id| {
        const node = ast.nodes.get(@intFromEnum(decl_node_id));
        switch (node.tag) {
            .fn_decl,
            .fn_proto,
            .fn_proto_one,
            .fn_proto_multi,
            .fn_proto_simple,
            .global_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            .container_field_init,
            .container_field,
            .container_field_align,
            => decl_count += 1,
            else => {},
        }
    }
    const root_decls = try arena.alloc(Declaration, decl_count);
    var decl: usize = 0;
    for (decls) |decl_node_id| {
        const node = ast.nodes.get(@intFromEnum(decl_node_id));
        const v: Declaration = switch (node.tag) {
            .fn_decl,
            .fn_proto,
            .fn_proto_one,
            .fn_proto_multi,
            .fn_proto_simple,
            => .{
                .node = decl_node_id,
                .name = tokenSource(ast, node.main_token + 1),
                .value = .{ .value = .func },
            },
            .simple_var_decl,
            .aligned_var_decl,
            .global_var_decl,
            => .{
                .node = decl_node_id,
                .name = tokenSource(ast, node.main_token + 1),
                .value = .{ .value = value: {
                    const var_decl = ast.fullVarDecl(decl_node_id).?;
                    break :value try getType(ast, var_decl.ast.type_node, arena) orelse (try getValue(ast, var_decl.ast.init_node, arena) orelse .leaf);
                } },
            },
            .container_field_init,
            .container_field,
            .container_field_align,
            => .{
                .node = decl_node_id,
                .name = tokenSource(ast, node.main_token),
                .value = .{ .value = value: {
                    const container_field = ast.fullContainerField(decl_node_id).?;
                    break :value if (!container_field.ast.tuple_like)
                        try getType(ast, container_field.ast.type_expr, arena) orelse .leaf
                    else
                        .leaf;
                } },
            },
            else => continue,
        };
        root_decls[decl] = v;
        decl += 1;
    }
    return .{ .composed_type = root_decls };
}
fn getType(ast: Ast, type_node: Ast.Node.OptionalIndex, arena: std.mem.Allocator) !?Declaration.Value {
    const i = type_node.unwrap() orelse return null;
    return switch (ast.nodeTag(i)) {
        .identifier => .{ .typeof_shortcut = shortcut: {
            const name = ast.tokenSlice(ast.nodeMainToken(i));
            if (std.mem.eql(u8, name, "type")) return null;
            const buf = try arena.alloc([]const u8, 1);
            buf[0] = try arena.dupe(u8, unraw(name));
            break :shortcut buf;
        } },
        .field_access => .{ .typeof_shortcut = shortcut: {
            var current_node = i;
            var identifier_count: usize = 1;
            while (ast.nodeTag(current_node) == .field_access) {
                identifier_count += 1;
                current_node = ast.nodeData(current_node).node_and_token.@"0";
            }
            if (ast.nodeTag(current_node) != .identifier) return null;
            const buf = try arena.alloc([]const u8, identifier_count);
            current_node = i;
            while (ast.nodeTag(current_node) == .field_access) {
                identifier_count -= 1;
                const node_data = ast.nodeData(current_node).node_and_token;
                buf[identifier_count] = try arena.dupe(u8, ast.tokenSlice(node_data.@"1"));
                current_node = node_data.@"0";
            }
            buf[0] = try arena.dupe(u8, ast.tokenSlice(ast.nodeMainToken(current_node)));
            break :shortcut buf;
        } },
        else => null,
    };
}
fn getValue(ast: Ast, decl: Ast.Node.OptionalIndex, arena: std.mem.Allocator) !?Declaration.Value {
    const i = decl.unwrap() orelse return null;
    return switch (ast.nodeTag(i)) {
        .container_decl,
        .container_decl_two,
        .container_decl_trailing,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_two,
        .tagged_union_trailing,
        .tagged_union_two_trailing,
        => container_decl: {
            var buf: [2]Ast.Node.Index = undefined;
            const container_decl = ast.fullContainerDecl(&buf, i) orelse return null;
            break :container_decl try getContainerDecl(ast, container_decl.ast.members, arena);
        },
        .identifier => .{ .equals_shortcut = shortcut: {
            const buf = try arena.alloc([]const u8, 1);
            buf[0] = try arena.dupe(u8, unraw(ast.tokenSlice(ast.nodeMainToken(i))));
            break :shortcut buf;
        } },
        .field_access => .{ .equals_shortcut = shortcut: {
            var current_node = i;
            var identifier_count: usize = 1;
            while (ast.nodeTag(current_node) == .field_access) {
                identifier_count += 1;
                current_node = ast.nodeData(current_node).node_and_token.@"0";
            }
            if (ast.nodeTag(current_node) != .identifier) return null;
            const buf = try arena.alloc([]const u8, identifier_count);
            current_node = i;
            while (ast.nodeTag(current_node) == .field_access) {
                identifier_count -= 1;
                const node_data = ast.nodeData(current_node).node_and_token;
                buf[identifier_count] = try arena.dupe(u8, ast.tokenSlice(node_data.@"1"));
                current_node = node_data.@"0";
            }
            buf[0] = try arena.dupe(u8, ast.tokenSlice(ast.nodeMainToken(current_node)));
            break :shortcut buf;
        } },
        //TODO implement
        .struct_init => null,

        .array_type, .optional_type, .anyframe_type, .array_type_sentinel, .ptr_type, .ptr_type_aligned, .ptr_type_sentinel, .ptr_type_bit_range => .type,
        else => null,
    };
}
