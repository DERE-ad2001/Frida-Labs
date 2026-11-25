-- Shared prelude: teach the agent thread the app classloader so Java.use()
-- resolves app classes (boot classes work without it). Inline this at the top
-- of each challenge script (Renef Lua has no require()).
local AT = Java.use('android/app/ActivityThread')
local app = AT:call('currentApplication', '()Landroid/app/Application;')
local cl = app:call('getClassLoader', '()Ljava/lang/ClassLoader;')
local t = Java.use('java/lang/Thread'):call('currentThread', '()Ljava/lang/Thread;')
t:call('setContextClassLoader', '(Ljava/lang/ClassLoader;)V', cl)
