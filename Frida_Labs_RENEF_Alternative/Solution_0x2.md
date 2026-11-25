## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x2/Challenge 0x2.apk`).
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

## Challenge 0x2

The app only shows a `HOOK ME!` TextView and never calls the method we want.
Decompilation shows `MainActivity.get_flag(I)V`: it checks whether the argument
is `4919` and, if so, decrypts a flag into the TextView. Since nothing calls it,
we have to call it ourselves.

Frida does that inside `Java.perform` and does not worry about threads. Renef
runs Lua on its own agent thread; calling an Android UI method from there hangs.
The fix is to post a `Runnable` to the main looper. `Java.registerClass` gives us
a Java class that implements `java/lang/Runnable`, and `Handler.post` runs its
`run()` method on the UI thread.

The class name again uses slashes: `com/ad2001/frida0x2/MainActivity`.

```lua
-- Frida Labs 0x2: call MainActivity.get_flag(4919) from the UI thread.
-- The method decrypts a flag and sets a TextView, so calling it from the
-- agent's background thread hangs/fails on Android; post a Runnable to the
-- main looper instead.

local AT = Java.use('android/app/ActivityThread')
local app = AT:call('currentApplication', '()Landroid/app/Application;')
local cl = app:call('getClassLoader', '()Ljava/lang/ClassLoader;')
local t = Java.use('java/lang/Thread'):call('currentThread', '()Ljava/lang/Thread;')
t:call('setContextClassLoader', '(Ljava/lang/ClassLoader;)V', cl)

local ok, err = pcall(function()
    local worker = Java.registerClass({
        implements = {"java/lang/Runnable"},
        methods = {
            run = function()
                local ok2, err2 = pcall(function()
                    Java.use('com/ad2001/frida0x2/MainActivity'):call('get_flag', '(I)V', 4919)
                end)
                print('[0x2] get_flag(4919) on UI thread: ' .. tostring(ok2) .. ' ' .. tostring(err2))
            end,
        },
    })
    local looper = Java.use('android/os/Looper'):call('getMainLooper', '()Landroid/os/Looper;')
    local handler = Java.use('android/os/Handler'):new('(Landroid/os/Looper;)V', looper)
    handler:call('post', '(Ljava/lang/Runnable;)Z', worker)
end)
if ok then print('[0x2] runnable posted to main thread') else print('[0x2] FAIL: ' .. tostring(err)) end
```

## Running it

Package: `com.ad2001.frida0x2`. Script: `challenge_0x2.lua`.

Reload the app before running this one, then load the script. No interaction is
needed — the posted Runnable calls `get_flag(4919)` by itself and the TextView
turns into `FLAG{BABY_HOOKS_0x2}`.

The `Java.registerClass` pattern is worth remembering; it is also used in the
bundled `ssl_unpin.lua` example for trust managers.
