local r_session = require("resty.session")

local M = {}

function M.apply_tenant_config(config)
  local session = r_session.open()
  if not session then return config end

  local tenant = session.data.selected_tenant
  if not tenant then return config end

  local tenant_subdomain = tenant.subdomain
  if tenant_subdomain then
    if config.introspection_endpoint then config.introspection_endpoint = string.gsub(config.introspection_endpoint, "://", "://" .. tenant_subdomain .. ".", 1) end
    if config.discovery then config.discovery = string.gsub(config.discovery, "://", "://" .. tenant_subdomain .. ".", 1) end
  end

  force = session.data.selected_tenant_force
  if force == "true" then
    kong.log("OIDC: force reauthorize")
    config.force_reauthorize = true
  end

  return config
end

return M
