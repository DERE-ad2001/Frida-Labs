-- Frida Labs 0x8: cmpstr(Ljava/lang/String;)I is a native method in
-- libfrida0x8.so. The app loads the library on first submit. Hook its JNI
-- export (offset 0x864, verified with readelf) and force return 1.

local ok, err = pcall(function()
    hook('libfrida0x8.so', 0x864, {
        onEnter = function(args)
            local p = Memory.readString(args[0])
            print('[0x8] cmpstr(' .. tostring(p) .. ')')
        end,
        onLeave = function(retval)
            print('[0x8] forcing cmpstr()=1 (was ' .. tostring(retval) .. ')')
            return 1
        end,
    })
end)
if ok then print('[0x8] cmpstr hook installed (deferred until lib loads)')
else print('[0x8] HOOK FAILED: ' .. tostring(err)) end
