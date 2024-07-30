local M = {}

local function shouldIgnoreRoute(ignored_routes)
  local route = kong.router.get_route()
  if route and ignored_routes then
    for _, ignored_route in ipairs(ignored_routes) do
      if (ignored_route == route.name) then return true end
    end
  end

  return false
end

function M.shouldIgnoreRoute(config)  
  return shouldIgnoreRoute(config.ignored_routes)
end

return M
