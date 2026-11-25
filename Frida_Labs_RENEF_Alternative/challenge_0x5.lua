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
