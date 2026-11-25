## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x1/Challenge 0x1.apk`).
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

## Challenge 0x1

If you open the app you get an input box and a Submit button. The decompiled
`MainActivity` has `get_random()I` and `check(II)V`. The button handler passes a
random number and your input to `check`, which compares the input with
`random * 2 + 4`.

The Frida solution hooks `get_random()` and returns a known value. On this
device that hook does not fire — the tiny static method gets inlined by ART into
`check`, so the app never calls the method we patched. What does fire is a hook
on `check(II)V`; its second argument is the random number. We log it, work out
the answer, and submit it on a second click.

The Renef template for a method hook is:

```lua
hook("class/name/Here", "methodName", "(signature)V", {
  onEnter = function(args) ... end,
  onLeave = function(retval) ... end,
})
```

Note the Java class uses slashes instead of dots and the full JNI signature is
required. Here is the real script:

```lua
-- Frida Labs 0x1 — hook a Java method and override its return value.
-- MainActivity.get_random()I supplies the random number passed to check(II)V.
-- check() compares input against random*2+4; forcing 100 means 204 is correct.

-- Renef's agent thread needs the app classloader before Java.use() can resolve
-- app classes (boot classes work without this).
local AT = Java.use('android/app/ActivityThread')
local app = AT:call('currentApplication', '()Landroid/app/Application;')
local cl = app:call('getClassLoader', '()Ljava/lang/ClassLoader;')
local t = Java.use('java/lang/Thread'):call('currentThread', '()Ljava/lang/Thread;')
t:call('setContextClassLoader', '(Ljava/lang/ClassLoader;)V', cl)

-- ART inlines the tiny static get_random()I into check(), so hooking that
-- static method does not intercept the UI path. Instead hook check(II)V
-- (an instance method, verified to fire) and log its random argument: the
-- correct input is random*2+4. Re-entering check() from inside the handler
-- crashes the agent on this build, so do not call Java from onEnter.
local ok, err = pcall(function()
    hook('com/ad2001/frida0x1/MainActivity', 'check', '(II)V', {
        onEnter = function(args)
            print('[0x1] check() random=' .. tostring(args[2])
                  .. ', expected input=' .. tostring((tonumber(args[2]) or 0) * 2 + 4))
        end,
    })
end)
if not ok then
    print('[0x1] HOOK FAILED: ' .. tostring(err))
else
    print('[0x1] check hook installed; submit any number to reveal the expected input')
end
```

## Running it

Package: `com.ad2001.frida0x1`. Script: `challenge_0x1.lua`.

1. Load the script, then type any number and press Submit. The hook prints the
   expected input in the MCP output (use `renef_watch` if you want to see it live).
2. Type the printed number and press Submit again.

The TextView changes to `FRIDA{BABY_HOOK_0x1}`.

One hard-earned rule: do **not** call a Java method from inside a hook handler
on this build. I tried re-entering `check()` from `onEnter` and it killed the
agent process. Two separate clicks are slower but reliable.
