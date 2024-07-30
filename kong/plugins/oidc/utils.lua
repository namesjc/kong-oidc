local cjson = require("cjson")

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

local function has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider - 1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

function M.get_redirect_uri_path(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      return path
    elseif path == "/" then
      return "/cb"
    elseif path:sub(-1) == "/" then
      return path:sub(1, -2)
    else
      return path .. "/"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    valid_issuers = config.valid_issuers,
    introspection_endpoint = config.introspection_endpoint,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri_path = config.redirect_uri_path or M.get_redirect_uri_path(ngx),
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters(config.filters),
    ignored_routes = config.ignored_routes,
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
    forward_bearer_access_token = config.forward_bearer_access_token,
    redirect_after_logout_with_id_token_hint = config.redirect_after_logout_with_id_token_hint,
    post_logout_redirect_uri = config.post_logout_redirect_uri,
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken)
  ngx.req.set_header("X-Access-Token", accessToken)
end

function M.injectBearerAccessToken(accessToken)
  local b = "Bearer " .. accessToken
  --[[
  kong.log.debug("utils.injectBearerAccessToken(): add Authorization: " .. b)
  --]]
  ngx.req.set_header("Authorization", b)
end

function M.injectIDToken(idToken)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header("X-ID-Token", ngx.encode_base64(tokenStr))
end

function M.injectUser(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.ctx.authenticated_credential = tmp_user
  local userinfo = cjson.encode(user)
  ngx.req.set_header("X-Userinfo", ngx.encode_base64(userinfo))
end

function M.has_bearer_access_token()
  return has_bearer_access_token()
end

function M.has_not_bearer_access_token()
  return not has_bearer_access_token()
end

function M.get_bearer_access_token()
  local token = ngx.req.get_headers()['Authorization']
  return string.gsub(token, "Bearer ", "")
end

function M.split(inp, sep)
  local t={}

  for str in string.gmatch(inp, "([^"..sep.."]+)") do
    table.insert(t, str)
    print(str)
  end

  return t
end

local exports = {}

local function escape(pattern)
  -- Auto-escape all magic characters in a string.
  return pattern:gsub("[%-%.%+%[%]%(%)%$%^%%%?%*]", "%%%1")
end

function M.to_pattern(wildcard_pattern)
  -- Parses a path query string into a proper Lua pattern string that can be
  -- used with find and gsub.

  -- Replace double-asterisk and single-asterisk query symbols with
  -- temporary tokens.
  local tokenized = wildcard_pattern
    :gsub("%*%*", "__DOUBLE_WILDCARD__")
    :gsub("%*", "__WILDCARD__")
    :gsub("%?", "__ANY_CHAR__")
  -- Then escape any magic characters.
  local escaped = escape(tokenized)
  -- Finally, replace tokens with true magic-character patterns.
  -- Double-asterisk will traverse any number of characters to make a match.
  -- single-asterisk will only traverse non-slash characters (i.e. in same dir).
  -- the ? will match any single character.
  local pattern = escaped
    :gsub("__DOUBLE_WILDCARD__", ".+")
    :gsub("__WILDCARD__", "[^.]+")
    :gsub("__ANY_CHAR__", ".")

  -- Make sure pattern matches from beginning of string.
  local bounded = "^" .. pattern

  return bounded
end

return M
