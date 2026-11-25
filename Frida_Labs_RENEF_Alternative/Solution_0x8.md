## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x8/Challenge 0x8.apk`).
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

## Challenge 0x8

This one is native. The input you type is passed to `cmpstr` in
`libfrida0x8.so`; returning 1 makes the app accept it. The library is loaded
when you first press Submit, not at startup.

Frida resolves the export with `Module.findExportByName`. In Renef we list
exports of a loaded module with `Module.exports`. From the arm64 library:

```
Java_com_ad2001_frida0x8_MainActivity_cmpstr   @ 0x864
```

Renef hooks on not-yet-loaded libraries are deferred automatically, so we can
install the hook before the first click. `onEnter` reads the argument with
`Memory.readString(args[0])`, and `onLeave` returns 1.

```lua
-- Frida Labs 0x8: cmpstr(Ljava/lang/String;)I is a native method in
-- libfrida0x8.so. The app loads the library on first submit. Hook its JNI
-- export (offset 0x864, verified with readelf) and force return 1.

local ok, err = pcall(function()
    hook('libfrida0x8.so', 0x864, {
        onEnter = function(args)
            local p = Memory.readString(args[0])
            print('[0x8] cmpstr(' .. tostring(p) .. ')')
        end,
        onLeave = function(retval)
            print('[0x8] forcing cmpstr()=1 (was ' .. tostring(retval) .. ')')
            return 1
        end,
    })
end)
if ok then print('[0x8] cmpstr hook installed (deferred until lib loads)')
else print('[0x8] HOOK FAILED: ' .. tostring(err)) end
```

## Running it

Package: `com.ad2001.frida0x8`. Script: `challenge_0x8.lua`.

Type something and press Submit. Android sometimes shows a translate popup
over the input; dismiss it and press Submit again. The hook prints the call and
forces the return value. A screenshot of the app shows
`YEY YOU GOT THE FLAG candidate` — the flag here is your input.

The dump of the argument looks like garbage because the JNI bridge passes a
`jstring` object rather than a `char*`; that is expected and harmless.
