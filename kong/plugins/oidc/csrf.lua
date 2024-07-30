local rand         = require("resty.openssl.rand")
local base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" -- You will need this for encoding/decoding
local M            = {}

function to_base64(data)
    -- from byte to binary
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    -- replace every 6 bits with base64 char
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return base64_chars:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

function generate(length)
  local bytes = rand.bytes(length)
  return to_base64(bytes)
end 

function M.set(session) 
    if session.data.csrf_token == nil then
      session.data.csrf_token = generate(32)
      kong.log.debug("CSRF: added to session - " .. session.data.csrf_token)
    end
end

return M
