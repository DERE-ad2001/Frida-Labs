## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0xA/Challenge 0xA.apk`).
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

## Challenge 0xA

The flag is produced by a native function `_Z8get_flagii` in
`libfrida0xa.so`. Frida calls it with `new NativeFunction(base.add(0x18BB0),
'void', ['int','int'])` and passes `(1, 2)` because the function checks that the
sum is 3.

Renef has no `NativeFunction`, so there is nothing to call from Lua. What the
app *does* call is `stringFromJNI()`, whose native entry is at `0x1dbe0`. We
patch its first twelve bytes with three ARM64 instructions:

```
mov w0, #1   ; 20 00 80 52
mov w1, #2   ; 41 00 80 52
b  0x1dd60  ; 5e 00 00 14   (branch to get_flag from 0x1dbe8)
```

`Memory.patch` handles the page protection for us. The next time the app calls
`stringFromJNI()`, it jumps into `get_flag(1,2)` instead.

```lua
-- Frida Labs 0xA: Renef has no NativeFunction, so instead of calling
-- _Z8get_flagii directly, patch the entry of stringFromJNI() (which the app
-- actually calls) to set w0=1, w1=2 and branch to get_flag@0x1dd60.
--   mov w0, #1   -> 20 00 80 52
--   mov w1, #2   -> 41 00 80 52
--   b 0x1dd60    -> 5e 00 00 14  (from 0x1dbe8: (0x1dd60-0x1dbe8)/4 = 0x5e)
-- get_flag(1,2) sums to 3 and logs the decoded flag with logcat tag FLAG.

local lib = 'libfrida0xa.so'
local base = Module.find(lib)
if not base then
    print('[0xA] ' .. lib .. ' not loaded yet; reload after the app draws')
    return
end

local target = base + 0x1dbe0
local ok, err = pcall(function()
    Memory.patch(target, '\x20\x00\x80\x52\x41\x00\x80\x52\x5e\x00\x00\x14')
end)
if not ok then
    print('[0xA] PATCH FAILED: ' .. tostring(err))
else
    local bytes = Memory.read(target, 12)
    local hex = ''
    for i = 1, 12 do hex = hex .. string.format('%02x', string.byte(bytes, i)) end
    print('[0xA] stringFromJNI entry patched: ' .. hex)
end
```

## Running it

Package: `com.ad2001.frida0xa`. Script: `challenge_0xA.lua`.

Load the script, then bring the app back to the foreground (an `am start` of
the activity is enough). Check logcat:

```
D FLAG    : Decrypted Flag: FRIDA{DONT_CALL_ME}
```

The patched function does not return a proper jstring any more, so the app's
TextView may show nothing. That is fine for this challenge — we only need the
flag in the log.
