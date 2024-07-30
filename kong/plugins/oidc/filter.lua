local M = {}

local function get_token_header_name(config)
  if (config.forward_bearer_access_token == "yes") then
    return "Authorization"
  else
    return "X-Access-Token"
  end
end

local function should_ingore_request(config)
  local token_header_name = get_token_header_name(config)
  local token_header = kong.request.get_header(token_header_name)
  if token_header then return true end

  local patterns = config.filters
  if (patterns) then
    for _, pattern in ipairs(patterns) do
      --local isMatching = not (string.find(ngx.var.uri, pattern) == nil)
      --if (isMatching) then return true end
      local isMatching = not (string.find(ngx.var.request_uri, pattern) == nil)
      if (isMatching) then return true end
    end
  end
  return false
end

function M.shouldIgnoreRequest(config)
  return should_ingore_request(config)
end

return M
