-- Frida Labs 0xA: Renef has no NativeFunction, so instead of calling
-- _Z8get_flagii directly, patch the entry of stringFromJNI() (which the app
-- actually calls) to set w0=1, w1=2 and branch to get_flag@0x1dd60.
--   mov w0, #1   -> 20 00 80 52
--   mov w1, #2   -> 41 00 80 52
--   b 0x1dd60    -> 5e 00 00 14  (from 0x1dbe8: (0x1dd60-0x1dbe8)/4 = 0x5e)
-- get_flag(1,2) sums to 3 and logs the decoded flag with logcat tag FLAG.

local lib = 'libfrida0xa.so'
local base = Module.find(lib)
if not base then
    print('[0xA] ' .. lib .. ' not loaded yet; reload after the app draws')
    return
end

local target = base + 0x1dbe0
local ok, err = pcall(function()
    Memory.patch(target, '\x20\x00\x80\x52\x41\x00\x80\x52\x5e\x00\x00\x14')
end)
if not ok then
    print('[0xA] PATCH FAILED: ' .. tostring(err))
else
    local bytes = Memory.read(target, 12)
    local hex = ''
    for i = 1, 12 do hex = hex .. string.format('%02x', string.byte(bytes, i)) end
    print('[0xA] stringFromJNI entry patched: ' .. hex)
end
