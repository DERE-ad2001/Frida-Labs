-- Frida Labs 0x9: native check_flag()I in liba0x9.so (first export /
-- Java_com_ad2001_a0x9_MainActivity_check_1flag @ 0x614). Renef defers
-- native hooks on not-yet-loaded libraries until they map.

local lib = 'liba0x9.so'
local base = Module.find(lib)
if not base then
    print('[0x9] ' .. lib .. ' not loaded yet; hook is deferred until it is')
end
local ok, err = pcall(function()
    hook(lib, 0x614, {
        onEnter = function(args)
            print('[0x9] check_flag called')
        end,
        onLeave = function(retval)
            print('[0x9] original retval=' .. tostring(retval) .. ', forcing 1337')
            return 1337
        end,
    })
end)
if ok then print('[0x9] check_flag hook installed')
else print('[0x9] HOOK FAILED: ' .. tostring(err)) end
