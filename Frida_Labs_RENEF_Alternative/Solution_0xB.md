## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0xB/Challenge 0xB.apk`).
- Basic jadx/dex skills and small Lua snippets.
- Important: this is Renef, not Frida. There is no `Java.perform`, no `Interceptor`,
  and no `NativeFunction`. The scripts below use the Renef Lua API instead.

## Getting ready

Start the app through the MCP with a gated spawn so the script runs before the
app's own code:

```
renef_spawn("<package>")
renef_load_script("<path-to-script>")
```

The first `renef_exec` (including `renef_load_script`) automatically resumes the
gated process. Nothing else needs to be attached.

## Challenge 0xB

The last one is about patching a branch. `getFlag()` in `libfrida0xb.so`
compares a local variable with `0x539` (1337). The comparison always fails, so
a `b.ne` at `0x15248` jumps past the flag decoder. Frida replaces that branch
with NOPs using `Arm64Writer` / `Memory.patchCode`.

Renef has a simpler `Memory.patch` that already deals with memory protection.
One NOP is enough on arm64 because the branch is a single 4-byte instruction:

```
54 07 00 54   (b.ne)   ->   1f 20 03 d5   (nop)
```

The library is loaded when you press CLICK ME, so click once first, then load
the script, then click again.

```lua
-- Frida Labs 0xB: getFlag() native code in libfrida0xb.so has a conditional
-- branch b.ne at 0x15248 (bytes 21 07 00 54) that skips the flag decoder.
-- Replace it with an ARM64 NOP (1f 20 03 d5) so execution falls through.

local lib = 'libfrida0xb.so'
local base = Module.find(lib)
if not base then
    print('[0xB] ' .. lib .. ' not loaded; tap CLICK ME once, then reload this script')
    return
end
local target = base + 0x15248
local before = Memory.read(target, 4)
local hex = ''
for i = 1, 4 do hex = hex .. string.format('%02x', string.byte(before, i)) end
local ok, err = pcall(function() Memory.patch(target, '\x1f\x20\x03\xd5') end)
if not ok then
    print('[0xB] PATCH FAILED: ' .. tostring(err))
else
    local after = Memory.read(target, 4)
    local hex2 = ''
    for i = 1, 4 do hex2 = hex2 .. string.format('%02x', string.byte(after, i)) end
    print('[0xB] patched b.ne @ 0x15248: ' .. hex .. ' -> ' .. hex2)
end
```

## Running it

Package: `com.ad2001.frida0xb`. Script: `challenge_0xB.lua`.

After the second click, logcat shows the flag:

```
D FLAG :  : FRIDA{NATIVE_HACKER}
```

The script prints the bytes before and after the patch; `21070054 ->
1f2003d5` means it worked.
