## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x7/Challenge 0x7.apk`).
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

## Challenge 0x7

This is 0x6 with one difference: the Checker has a two-argument constructor.
Frida calls `$new(600, 600)`. The Frida solution also mentions that hooking the
constructor was broken on ARM64, which is another reason to just create the
object ourselves.

In Renef we use `:new("(II)V", 600, 600)` — the constructor signature goes
first, then the arguments — and then invoke `flag(checker)` on the live
MainActivity using the same reflection code as before.

```lua
-- Frida Labs 0x7: invoke flag(1337) on the EXISTING MainActivity instance.
-- Renef has no Java.choose, so enumerate ActivityThread.mActivities via
-- reflection, pick the MainActivity instance, find its declared `flag`
-- method, and invoke it with an Integer 1337.

local AT = Java.use('android/app/ActivityThread')
local app = AT:call('currentApplication', '()Landroid/app/Application;')
local cl = app:call('getClassLoader', '()Ljava/lang/ClassLoader;')
Java.use('java/lang/Thread'):call('currentThread', '()Ljava/lang/Thread;')
    :call('setContextClassLoader', '(Ljava/lang/ClassLoader;)V', cl)

local Array = Java.use('java/lang/reflect/Array')
local function entries(java_array)
    local out = {}
    local n = Array:call('getLength', '(Ljava/lang/Object;)I', java_array)
    for i = 0, n - 1 do
        out[#out + 1] = Array:call('get', '(Ljava/lang/Object;I)Ljava/lang/Object;', java_array, i)
    end
    return out
end

local ok, err = pcall(function()
    local thread = AT:call('currentActivityThread', '()Landroid/app/ActivityThread;')
    local field = thread:call('getClass', '()Ljava/lang/Class;')
        :call('getDeclaredField', '(Ljava/lang/String;)Ljava/lang/reflect/Field;', 'mActivities')
    field:call('setAccessible', '(Z)V', true)
    local map = field:call('get', '(Ljava/lang/Object;)Ljava/lang/Object;', thread)
    local records = entries(map:call('values', '()Ljava/util/Collection;'):call('toArray', '()[Ljava/lang/Object;'))

    for _, record in ipairs(records) do
        local af = record:call('getClass', '()Ljava/lang/Class;')
            :call('getDeclaredField', '(Ljava/lang/String;)Ljava/lang/reflect/Field;', 'activity')
        af:call('setAccessible', '(Z)V', true)
        local activity = af:call('get', '(Ljava/lang/Object;)Ljava/lang/Object;', record)
        if activity then
            local class_name = activity:call('getClass', '()Ljava/lang/Class;'):call('getName', '()Ljava/lang/String;')
            if class_name == 'com.ad2001.frida0x7.MainActivity' then
                local methods = entries(activity:call('getClass', '()Ljava/lang/Class;')
                    :call('getDeclaredMethods', '()[Ljava/lang/reflect/Method;'))
                for _, method in ipairs(methods) do
                    if method:call('getName', '()Ljava/lang/String;') == 'flag' then
                        method:call('setAccessible', '(Z)V', true)
                        local checker = Java.use('com/ad2001/frida0x7/Checker'):new('(II)V', 600, 600)
                        method:call('invoke', '(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;',
                            activity, Java.array('java/lang/Object', { checker }))
                        print('[0x7] flag(1337) invoked on the live MainActivity')
                        return
                    end
                end
            end
        end
    end
    error('MainActivity/flag not found among activity records')
end)
if not ok then print('[0x7] FAIL: ' .. tostring(err)) end
```

## Running it

Package: `com.ad2001.frida0x7`. Script: `challenge_0x7.lua`.

Load the script with the app already open. The result is
`FRIDA{HOOKING_CONSTRUCTORS}` in the TextView.

If you are adapting this to another constructor, get the signature from jadx and
write it exactly as it appears, with `Lpackage/Class;` for object parameters.
