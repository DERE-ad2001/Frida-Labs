## Prerequisites

- A rooted ARM64 Android device with `adb` access.
- `renef_server` running on the device and `android-renef-mcp` registered in your MCP client.
- The challenge APK installed (`~/github/Frida_Labs/Frida 0x5/Challenge 0x5.apk`).
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

## Challenge 0x5

The app has a `flag(I)V` method on `MainActivity`, but nothing ever calls it —
exactly the case where Frida's `Java.choose` shines. Renef does not have
`Java.choose`, so we find the live Activity another way.

Every Android app has an `ActivityThread` with an `mActivities` map. Using plain
reflection (`getDeclaredField`, `setAccessible`, `java.lang.reflect.Array`) we
walk that map, find the `MainActivity` instance, locate its declared `flag`
method, and invoke it with an `Integer` wrapper for `1337`.

The reflection helpers are a bit verbose, but they are reusable for the next two
challenges too.

```lua
-- Frida Labs 0x5: invoke flag(1337) on the EXISTING MainActivity instance.
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
            if class_name == 'com.ad2001.frida0x5.MainActivity' then
                local methods = entries(activity:call('getClass', '()Ljava/lang/Class;')
                    :call('getDeclaredMethods', '()[Ljava/lang/reflect/Method;'))
                for _, method in ipairs(methods) do
                    if method:call('getName', '()Ljava/lang/String;') == 'flag' then
                        method:call('setAccessible', '(Z)V', true)
                        local arg = Java.use('java/lang/Integer'):call('valueOf', '(I)Ljava/lang/Integer;', 1337)
                        method:call('invoke', '(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;',
                            activity, Java.array('java/lang/Object', { arg }))
                        print('[0x5] flag(1337) invoked on the live MainActivity')
                        return
                    end
                end
            end
        end
    end
    error('MainActivity/flag not found among activity records')
end)
if not ok then print('[0x5] FAIL: ' .. tostring(err)) end
```

## Running it

Package: `com.ad2001.frida0x5`. Script: `challenge_0x5.lua`.

Load the script while the app is in the foreground. It finds the instance and
calls the method; the TextView becomes `FRIDA{ON_MATCH_THIS_INSTANCE}`.

If the app has more than one Activity record (it usually has two), the script
checks the class name instead of guessing an index.
