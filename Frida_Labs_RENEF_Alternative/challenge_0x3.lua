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
