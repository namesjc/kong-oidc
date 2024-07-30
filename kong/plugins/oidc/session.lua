local utils = require("kong.plugins.oidc.utils")

local M = {}

function M.configure(config)
  if config.session_secret then
    local decoded_session_secret = ngx.decode_base64(config.session_secret)
    if not decoded_session_secret then
      utils.exit(500, "invalid OIDC plugin configuration, session secret could not be decoded", ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR))
    end
    kong.log.debug("OidcHandler setting session secret to: " .. decoded_session_secret)
    kong.log.debug("OidcHandler session secret undecoded: " .. config.session_secret)
    kong.log.debug("OidcHandler uri: " .. ngx.var.request_uri)
    kong.log.debug("OidcHandler method: " .. ngx.var.request_method)
    ngx.var.session_secret = decoded_session_secret
  end
end

return M
