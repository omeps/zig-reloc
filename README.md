# zig-reloc: A command line utility for creating namespaces from translate-c output

### Example usage
On file include.h:
```c
#include <vulkan/vulkan.h>
#include <SDL3/SDL.h>
```
this command will create namespaces for vulkan and SDL and fix any shadowing issues:

`zig translate-c -lc include.h | zig-reloc -n Vk vk -n vk vk -n VK_ vk -n SDL_ sdl -n PRI pri -n SIZE_ size_ -o out.zig --checked`

Each namespace is defined by a `-n`, a prefix to strip from declarations and a new name.

`--checked` runs the output through `zig ast-check` for you.

Namespaces with the same name **defined next to each other** will be concatenated.

### Building

zig-reloc is built on zig version `0.15.0-dev.936+fc2c1883b`. I will move it to `0.15` when that is released. There are no additional dependencies.

Build command:

`zig build run -Doptimize=ReleaseFast`

zig-reloc will be built at `zig-out/bin/zig-reloc`
