-- A presentation profile for an HTTP service, not a SIP implementation.
-- Only the first complete request line is inspected. Valid HTTP request lines,
-- including HTTP OPTIONS and bodies containing SIP text, are left untouched.
local M = {}

M.max_prefix = 8192
M.response = "HTTP/1.0 200 OK\r\n"
  .. "Allow: OPTIONS, GET, HEAD, POST\r\n"
  .. "Content-Length: 0\r\n"
  .. "Connection: close\r\n\r\n"

function M.decide(prefix)
  if type(prefix) ~= "string" or #prefix > M.max_prefix then
    return { action = "pass" }
  end
  local line = prefix:match("^([^\r\n]*)\r\n")
  -- Printable ASCII URI bytes, one space between fields, and a CRLF-terminated
  -- SIP/2.0 request line. This is intentionally narrower than full SIP syntax.
  if line and line:match("^OPTIONS sips?:[!-~]+ SIP/2%.0$") then
    return { action = "reply", response = M.response }
  end
  return { action = "pass" }
end

return M
