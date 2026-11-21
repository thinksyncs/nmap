local source = debug.getinfo(1, "S").source:sub(2)
local directory = source:match("^(.*[/\\])") or "./"
local profile = dofile(directory .. "../lua/dionaea_sip.lua")
local cases = {
  {"Nmap SIPOptions", "OPTIONS sip:nm SIP/2.0\r\n", "reply"},
  {"SIPS URI", "OPTIONS sips:user@example.test SIP/2.0\r\n", "reply"},
  {"SIP URI with parameters", "OPTIONS sip:user@127.0.0.1;transport=tcp SIP/2.0\r\n", "reply"},
  {"HTTP OPTIONS 1.1", "OPTIONS / HTTP/1.1\r\n", "pass"},
  {"HTTP OPTIONS 1.0", "OPTIONS * HTTP/1.0\r\n", "pass"},
  {"HTTP absolute SIP URI", "OPTIONS sip:nm HTTP/1.1\r\n", "pass"},
  {"HTTP request body", "POST /data HTTP/1.1\r\nContent-Length: 28\r\n\r\nOPTIONS sip:nm SIP/2.0\r\n", "pass"},
  {"HTTP subsequent request", "GET / HTTP/1.1\r\n\r\nOPTIONS sip:nm SIP/2.0\r\n", "pass"},
  {"SIP INVITE", "INVITE sip:nm SIP/2.0\r\n", "pass"},
  {"Lowercase method", "options sip:nm SIP/2.0\r\n", "pass"},
  {"Unknown version", "OPTIONS sip:nm SIP/3.0\r\n", "pass"},
  {"Extra token", "OPTIONS sip:nm SIP/2.0 extra\r\n", "pass"},
  {"Space inside URI", "OPTIONS sip:n m SIP/2.0\r\n", "pass"},
  {"Empty URI", "OPTIONS sip: SIP/2.0\r\n", "pass"},
  {"Tab in URI", "OPTIONS sip:n\tm SIP/2.0\r\n", "pass"},
  {"NUL in URI", "OPTIONS sip:n\0m SIP/2.0\r\n", "pass"},
  {"DEL in URI", "OPTIONS sip:n\127m SIP/2.0\r\n", "pass"},
  {"Bare LF", "OPTIONS sip:nm SIP/2.0\n", "pass"},
  {"Leading empty line", "\r\nOPTIONS sip:nm SIP/2.0\r\n", "pass"},
  {"Over-limit prefix", "OPTIONS sip:nm SIP/2.0\r\n" .. string.rep("x", 8192), "pass"},
  {"Non-string input", false, "pass"},
}
local expected = "HTTP/1.0 200 OK\r\nAllow: OPTIONS, GET, HEAD, POST\r\n"
  .. "Content-Length: 0\r\nConnection: close\r\n\r\n"
for _, case in ipairs(cases) do
  local result = profile.decide(case[2])
  assert(result.action == case[3], case[1] .. ": unexpected action")
  if result.action == "reply" then
    assert(result.response == expected, case[1] .. ": changed fingerprint bytes")
  else
    assert(result.response == nil, case[1] .. ": pass must not invent a response")
  end
end
local request = "OPTIONS sip:nm SIP/2.0\r\n"
for length = 0, #request - 1 do
  assert(profile.decide(request:sub(1, length)).action == "pass",
    "Incomplete request line must not trigger a reply at length " .. length)
end
print(string.format("profile cases: %d passed; incomplete-line boundary checks: %d passed", #cases, #request))
