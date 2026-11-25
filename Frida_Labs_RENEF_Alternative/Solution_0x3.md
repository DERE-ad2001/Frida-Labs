## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x3/Challenge 0x3.apk`).
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

## Challenge 0x3

Here the app has a `Checker` class with a static `code` field and an
`increase()` method. The button checks whether `code` reached `512`; if it did,
it shows the flag. Frida simply writes `Checker.code.value = 512`.

Renef has no way to write a static field — `Java.use` gives wrappers with
`new`/`call` only. But `increase()` adds one each time, so calling it 256 times
gets us to the same value. Less elegant, same result.

```lua
-- Shared prelude: teach the agent thread the app classloader so Java.use()
-- resolves app classes (boot classes work without it). Inline this at the top
-- of each challenge script (Renef Lua has no require()).
local AT = Java.use('android/app/ActivityThread')
local app = AT:call('currentApplication', '()Landroid/app/Application;')
local cl = app:call('getClassLoader', '()Ljava/lang/ClassLoader;')
local t = Java.use('java/lang/Thread'):call('currentThread', '()Ljava/lang/Thread;')
t:call('setContextClassLoader', '(Ljava/lang/ClassLoader;)V', cl)

-- Frida Labs 0x3: Checker.code must reach 512. Renef cannot write static
-- fields, but Checker.increase() adds one per call: 256 calls == 512.
local ok, err = pcall(function()
    local checker = Java.use('com/ad2001/frida0x3/Checker')
    for _ = 1, 256 do checker:call('increase', '()V') end
end)
if ok then print('[0x3] increase() called 256 times') else print('[0x3] FAIL: ' .. tostring(err)) end
```

## Running it

Package: `com.ad2001.frida0x3`. Script: `challenge_0x3.lua`.

Load the script and press the Click me button. Watch for a Toast and a TextView
reading `FRIDA{INJECT_AND_INSPECT}`.

If you run the script twice without restarting the app, `code` will be 1024 and
the check fails again. Restart between attempts.
