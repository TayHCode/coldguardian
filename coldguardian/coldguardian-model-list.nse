local http = require "http"
local json = require "json"
local shortport = require "shortport"

description = "Checks whether an OpenAI-compatible model list is reachable without credentials."
categories = {"safe", "discovery"}
portrule = shortport.http

local path = "/v1/models"

action = function(host, port)
  local response = http.get(host, port, path, {
    redirect_ok = false,
    bypass_cache = true,
    timeout = 3000,
    max_body_size = 65536,
    truncated_ok = false,
  })
  if response.status ~= 200 or type(response.body) ~= "string" then
    return
  end

  local parsed, models = json.parse(response.body)
  if not parsed or json.typeof(models) ~= "object" or models.object ~= "list" or json.typeof(models.data) ~= "array" then
    return
  end
  for _, model in ipairs(models.data) do
    if json.typeof(model) ~= "object" or type(model.id) ~= "string" or model.id:match("^%s*$") then
      return
    end
  end
  return { [path] = { "200 model list" } }
end
