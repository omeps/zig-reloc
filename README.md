# zig-reloc: A command line utility for creating namespaces from translate-c output

### Example usage
On file include.h:
```c
#include <vulkan/vulkan.h>
```
this command will create namespaces for vulkan and rename declarations to the canonical Zig style:

`zig translate-c -lc include.h | zig-reloc in.zig -n Vk vk -n vk vk -n VK_ vk -o out.zig --checked --formatted --styled`

Each namespace is defined by a `-n`, a prefix to strip from declarations and a new name.

`--checked` runs the output through `zig ast-check` for you. This command will call the system's zig.

`--formatted` runs the output through `zig fmt` for you. This is necessary for autocomplete with zls because of how zig-reloc currently handles raw identifiers. This command will call the system's zig.

`--styled` renames all moved declarations to the canonical Zig style 

Namespaces with the same name **defined next to each other** will be concatenated.

### Building

zig-reloc is always built on the latest zig version since the last commit (currently `0.15.0-dev.1429+04fe1bfe3`). I will move it to `0.15` when that is released. There are no additional build dependencies.

Build command:

`zig build run -Doptimize=ReleaseFast`

zig-reloc will be built at `zig-out/bin/zig-reloc`
