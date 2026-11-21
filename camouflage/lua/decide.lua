-- Bounded stdin/stdout bridge for the reference transport adapter.
-- No request bytes are evaluated as Lua source or used as a filename.
local source = debug.getinfo(1, "S").source:sub(2)
local directory = source:match("^(.*[/\\])") or "./"
local profile = dofile(directory .. "dionaea_sip.lua")
local prefix = io.stdin:read(profile.max_prefix + 1) or ""
local decision = profile.decide(prefix)
if decision.action == "reply" then
  io.stdout:write("REPLY\n", decision.response)
else
  io.stdout:write("PASS\n")
end
