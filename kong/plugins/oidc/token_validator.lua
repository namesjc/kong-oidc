local jwt = require("kong.plugins.oidc.jwt");
local utils = require("kong.plugins.oidc.utils")

local M = {}

local function is_valid_issuer(config, token)
    if not config.valid_issuers then return false end
    if not token then return false end

    kong.log.debug("OIDC.issuer: decode token")
    local decoded = jwt.decode(token)
    local issuer = decoded.claims["iss"]
    local is_valid = false

    kong.log.debug("OIDC.issuer: issuer " .. issuer)


    for i, valid_issuer in ipairs(config.valid_issuers) do
      local pattern = utils.to_pattern(valid_issuer)
      local match = string.match(issuer, pattern)
      kong.log.debug("OIDC.issuer: issuer pattern " .. valid_issuer)
      kong.log.debug("OIDC.issuer: lua pattern " .. pattern)

      if match == issuer then
        kong.log.debug("OIDC.issuer: Issuer matches pattern")
        is_valid = true 
      end
    end
    
    if not is_valid then 
      kong.log.debug("OIDC.issuer: Issuer does not match any pattern")
      return false 
    end

    local issuer_parts = utils.split(issuer, "/")
    local introspection_endpoint = issuer_parts[1] .. "//" .. issuer_parts[2] .. "/introspect"
    config.introspection_endpoint = introspection_endpoint
    kong.log.debug("OIDC.issuer: issuer introspection endpoint " .. introspection_endpoint)

    return true
end

function M.is_valid_issuer(config, token)
  return is_valid_issuer(config, token)
end

function M.is_not_valid_issuer(config, token)
  return not is_valid_issuer(config, token)
end

return M
