## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x4/Challenge 0x4.apk`).
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

## Challenge 0x4

There is nothing in `MainActivity`. The interesting class is `Check`, with an
instance method `get_flag(I)Ljava/lang/String;`. It XOR-decodes a string using
the key `15`, but only when the argument is `1337`. The method is never called
by the app.

Frida uses `$new()` and `console.log`. In Renef we use `:new("()V")` and
`print()`. Java strings come back as Lua strings, so concatenation works
directly.

```lua
-- Shared prelude: teach the agent thread the app classloader so Java.use()
-- resolves app classes (boot classes work without it). Inline this at the top
-- of each challenge script (Renef Lua has no require()).
local AT = Java.use('android/app/ActivityThread')
local app = AT:call('currentApplication', '()Landroid/app/Application;')
local cl = app:call('getClassLoader', '()Ljava/lang/ClassLoader;')
local t = Java.use('java/lang/Thread'):call('currentThread', '()Ljava/lang/Thread;')
t:call('setContextClassLoader', '(Ljava/lang/ClassLoader;)V', cl)

-- Frida Labs 0x4: instantiate Check and call get_flag(1337). The flag is
-- returned to the caller (Frida console only in the original solution).
local ok, result = pcall(function()
    local check = Java.use('com/ad2001/frida0x4/Check'):new('()V')
    return check:call('get_flag', '(I)Ljava/lang/String;', 1337)
end)
if ok and result then print('FLAG ' .. tostring(result)) else print('[0x4] FAIL: ' .. tostring(result)) end
```

## Running it

Package: `com.ad2001.frida0x4`. Script: `challenge_0x4.lua`.

Spawn the app and load the script. There is no UI change in this challenge —
the flag appears in the MCP output:

```
FLAG FRIDA{XORED_INSTANCE}
```

If `:new()` returns nil, the class has not been loaded yet; click the app once
(or restart it) and run the script again.
