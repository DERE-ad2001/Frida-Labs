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
