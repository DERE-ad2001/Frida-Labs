-- Frida Labs 0xB: getFlag() native code in libfrida0xb.so has a conditional
-- branch b.ne at 0x15248 (bytes 21 07 00 54) that skips the flag decoder.
-- Replace it with an ARM64 NOP (1f 20 03 d5) so execution falls through.

local lib = 'libfrida0xb.so'
local base = Module.find(lib)
if not base then
    print('[0xB] ' .. lib .. ' not loaded; tap CLICK ME once, then reload this script')
    return
end
local target = base + 0x15248
local before = Memory.read(target, 4)
local hex = ''
for i = 1, 4 do hex = hex .. string.format('%02x', string.byte(before, i)) end
local ok, err = pcall(function() Memory.patch(target, '\x1f\x20\x03\xd5') end)
if not ok then
    print('[0xB] PATCH FAILED: ' .. tostring(err))
else
    local after = Memory.read(target, 4)
    local hex2 = ''
    for i = 1, 4 do hex2 = hex2 .. string.format('%02x', string.byte(after, i)) end
    print('[0xB] patched b.ne @ 0x15248: ' .. hex .. ' -> ' .. hex2)
end
