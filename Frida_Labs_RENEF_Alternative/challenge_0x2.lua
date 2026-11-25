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
