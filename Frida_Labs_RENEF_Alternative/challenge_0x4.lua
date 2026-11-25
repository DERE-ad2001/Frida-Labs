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
