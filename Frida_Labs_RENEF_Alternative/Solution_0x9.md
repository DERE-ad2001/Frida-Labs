## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x9/Challenge 0x9.apk`).
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

## Challenge 0x9

Note the package name is `com.ad2001.a0x9`, not `frida0x9`. Pressing CLICK ME
calls a native `check_flag()I` which returns 1. The Frida solution attaches to
the first export and replaces the return value with 1337.

Renef's native hooks work the same way: `hook(lib, offset, {...})` with an
`onLeave` that returns an integer. The arm64 symbol is:

```
Java_com_ad2001_a0x9_MainActivity_check_1flag  @ 0x614
```

The bundled `dere_0x9.lua` example uses exactly this pattern; this script is a
slightly more verbose version with logging.

```lua
-- Frida Labs 0x9: native check_flag()I in liba0x9.so (first export /
-- Java_com_ad2001_a0x9_MainActivity_check_1flag @ 0x614). Renef defers
-- native hooks on not-yet-loaded libraries until they map.

local lib = 'liba0x9.so'
local base = Module.find(lib)
if not base then
    print('[0x9] ' .. lib .. ' not loaded yet; hook is deferred until it is')
end
local ok, err = pcall(function()
    hook(lib, 0x614, {
        onEnter = function(args)
            print('[0x9] check_flag called')
        end,
        onLeave = function(retval)
            print('[0x9] original retval=' .. tostring(retval) .. ', forcing 1337')
            return 1337
        end,
    })
end)
if ok then print('[0x9] check_flag hook installed')
else print('[0x9] HOOK FAILED: ' .. tostring(err)) end
```

## Running it

Package: `com.ad2001.a0x9`. Script: `challenge_0x9.lua`.

Spawn the app, load the script, press CLICK ME. The hook prints the original
return value and the forced one, and a Toast appears:
`You won FRIDA{NATIVE_LAND_0x2}`.

If the hook is installed while the library is still loading, Renef defers it;
you will see a note about that in the output.
