local json = require "cjson"
local basexx = require "basexx"

local rep = string.rep
local sub = string.sub
local find = string.find
local type = type
local pcall = pcall
local unpack = unpack
local decode_base64 = basexx.from_base64

local alg_verify = {
  HS256 = "HS256",
  HS384 = "HS384",
  HS512 = "HS512",
  RS256 = "RS256",
  RS512 = "RS512",
  ES256 = "ES256"
}

--- base 64 decode
-- @param input String to base64 decode
-- @return Base64 decoded string
local function base64_decode(input)
  local remainder = #input % 4

  if remainder > 0 then
    local padlen = 4 - remainder
    input = input .. rep("=", padlen)
  end

  input = input:gsub("-", "+"):gsub("_", "/")
  return decode_base64(input)
end

--- Tokenize a string by delimiter
-- Used to separate the header, claims and signature part of a JWT
-- @param str String to tokenize
-- @param div Delimiter
-- @param len Number of parts to retrieve
-- @return A table of strings
local function tokenize(str, div, len)
  local result, pos = {}, 0

  local iter = function()
    return find(str, div, pos, true)
  end

  for st, sp in iter do
    result[#result + 1] = sub(str, pos, st-1)
    pos = sp + 1
    len = len - 1
    if len <= 1 then
      break
    end
  end

  result[#result + 1] = sub(str, pos)
  return result
end


--- Parse a JWT
-- Parse a JWT and validate header values.
-- @param token JWT to parse
-- @return A table containing base64 and decoded headers, claims and signature
local function decode_token(token)
  -- Get b64 parts
  local header_64, claims_64, signature_64 = unpack(tokenize(token, ".", 3))

  -- Decode JSON
  local ok, header, claims, signature = pcall(function()
    return json.decode(base64_decode(header_64)),
           json.decode(base64_decode(claims_64)),
           base64_decode(signature_64)
  end)
  if not ok then
    return nil, "invalid JSON"
  end

  if not header.alg or type(header.alg) ~= "string" or not alg_verify[header.alg] then
    return nil, "invalid alg"
  end

  if not claims then
    return nil, "invalid claims"
  end

  if not signature then
    return nil, "invalid signature"
  end

  return {
    token = token,
    header_64 = header_64,
    claims_64 = claims_64,
    signature_64 = signature_64,
    header = header,
    claims = claims,
    signature = signature
  }
end

local M = {}
function M.decode(token)
  return decode_token(token);
end

return M