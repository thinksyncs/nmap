-- Candidate script contracts with fake sockets, not real-service evidence.
local stdnse = require "stdnse"
local unittest = require "unittest"
local M = {}

local function step(method, status, response, buffered)
  return { method = method, status = status, response = response, buffered = buffered }
end

local function connected()
  return { step("connect", true) }
end

local function banner_received()
  local steps = connected()
  steps[#steps + 1] = step("banner", true, "NetBus 1.70")
  return steps
end

local function probe_sent()
  local steps = banner_received()
  steps[#steps + 1] = step("send", true)
  return steps
end

local function run_case(case)
  local root = stdnse.get_script_args("classifier.root")
  assert(type(root) == "string", "classifier.root must point to the repository root")
  local host = { ip = "127.0.0.1" }
  local port = {
    number = 12345, protocol = "tcp", state = "open", service = "netbus",
    version = {
      name = "netbus", product = "previous product", version = "previous version",
      extrainfo = "previous information", name_confidence = 10,
    },
  }
  local expected_port = {
    number = 12345, protocol = "tcp", state = "open", service = "netbus",
    version = {
      name = "netbus", product = "previous product", version = "previous version",
      extrainfo = "previous information", name_confidence = 10,
    },
  }
  if case.matched then
    expected_port.version.product = "NetBuster"
    expected_port.version.version = "1.31"
    expected_port.version.extrainfo = "honeypot"
  end
  local original_version = port.version
  local cursor, closes, opens, publications = 1, 0, 0, 0
  local logs = {}
  local socket = {}

  local function next_step(method)
    local expected = case.steps[cursor]
    assert(expected, "unexpected socket operation: " .. method)
    assert(expected.method == method,
      "expected socket operation " .. expected.method .. ", got " .. method)
    assert(closes == 0, "socket used after close")
    cursor = cursor + 1
    return expected
  end

  function socket:set_timeout(timeout)
    assert(type(timeout) == "number" and timeout > 0, "socket timeout must be positive")
  end
  function socket:connect(actual_host, actual_port)
    assert(actual_host == host and actual_port == port, "probe target changed")
    local result = next_step("connect")
    return result.status, result.response
  end
  function socket:receive_buf(delimiter, keep)
    local result
    if type(delimiter) == "string" then
      assert(delimiter == "\r" and keep == false, "expected a complete CR-delimited banner")
      result = next_step("banner")
    else
      assert(type(delimiter) == "function" and keep == true, "expected a fixed-size fingerprint")
      for length = 0, 7 do
        assert(delimiter(string.rep("x", length)) == nil, "fingerprint accepts too few bytes")
      end
      local first, last = delimiter("1.31-1-1234")
      assert(first == 8 and last == 8, "fingerprint must consume exactly eight bytes")
      result = next_step("fingerprint")
      if result.buffered then
        assert(delimiter(result.buffered) == nil, "partial fixture already satisfies the read")
      end
    end
    return result.status, result.response
  end
  function socket:send(data)
    assert(data == "nbver\rGetInfo\r", "unexpected query pair or state-changing argument")
    local result = next_step("send")
    return result.status, result.response
  end
  function socket:close()
    closes = closes + 1
    return true
  end

  local fake_nmap = {
    new_socket = function()
      opens = opens + 1
      return socket
    end,
    set_port_version = function(actual_host, actual_port)
      assert(case.matched, "uncertain or mismatching observations published an identification")
      assert(actual_host == host and actual_port == port, "published identification for the wrong target")
      publications = publications + 1
    end,
  }
  local fake_stdnse = {
    debug1 = function(format, ...)
      logs[#logs + 1] = string.format(format, ...)
    end,
  }
  local environment = setmetatable({
    require = function(name)
      if name == "nmap" then return fake_nmap end
      if name == "stdnse" then return fake_stdnse end
      return require(name)
    end,
  }, { __index = _G })
  local chunk, load_error = loadfile(root .. "/nse/netbus-version.nse", "t", environment)
  assert(chunk, load_error)
  chunk()
  assert(type(environment.action) == "function", "candidate did not define action")
  local result = environment.action(host, port)

  assert(result == nil, "version script must not add ordinary script output")
  assert(opens == 1, "expected one socket")
  assert(closes == 1, "socket must be closed exactly once")
  assert(cursor == #case.steps + 1, "expected socket operations were skipped")
  assert(publications == (case.matched and 1 or 0), "unexpected identification publication count")
  assert(port.version == original_version, "port.version was replaced")
  local correct, comparison = unittest.identical(port, expected_port)()
  assert(correct, comparison)
  if case.reason then
    local expected_log = case.reason .. (case.error and ": " .. case.error or "")
    assert(#logs == 1 and logs[1] == expected_log, "failure reason or transport error was lost")
  end
end

local cases = {}
local function add_case(name, steps, matched, reason, err)
  cases[#cases + 1] = {
    name = name, steps = steps, matched = matched, reason = reason, error = err,
  }
end

for reminder = 0, 4 do
  local steps = probe_sent()
  steps[#steps + 1] = step("fingerprint", true, "1.31-" .. reminder .. "-1")
  add_case("candidate prefix with reminder " .. reminder, steps, true)
end

for _, response in ipairs({ "1.30-1-1", "1.32-1-1", "1.31-5-1", "1.31-x-1", "1.31-1-x", "1x31-1-1", "Access;0", "Info;Pro", "Info;Sor" }) do
  local steps = probe_sent()
  steps[#steps + 1] = step("fingerprint", true, response)
  add_case("nonmatching prefix " .. response, steps, false, "fingerprint_mismatch")
end

local steps = connected()
steps[#steps + 1] = step("banner", true, "SSH-2.0-synthetic")
add_case("unrelated banner returns nil and closes the socket", steps, false, "unrelated_banner")

-- Both documented failure statuses must leave existing metadata untouched.
for _, failure in ipairs({ { name = "nil" }, { name = "false", value = false } }) do
  add_case("connect failure with " .. failure.name,
    { step("connect", failure.value, "ERROR") }, false, "connection_failed", "ERROR")

  steps = banner_received()
  steps[#steps + 1] = step("send", failure.value, "ERROR")
  add_case("send failure with " .. failure.name, steps, false, "version_send_failed", "ERROR")

  for _, err in ipairs({ "TIMEOUT", "EOF" }) do
    steps = connected()
    steps[#steps + 1] = step("banner", failure.value, err)
    add_case("banner " .. err .. " with " .. failure.name, steps, false, "banner_receive_failed", err)

    steps = probe_sent()
    steps[#steps + 1] = step("fingerprint", failure.value, err)
    add_case("version " .. err .. " with " .. failure.name, steps, false, "version_receive_failed", err)
  end
end

for length = 1, 7 do
  for _, err in ipairs({ "TIMEOUT", "EOF" }) do
    steps = probe_sent()
    steps[#steps + 1] = step("fingerprint", false, err, ("1.31-1-1"):sub(1, length))
    add_case(length .. " prefix bytes then " .. err, steps, false, "version_receive_failed", err)
  end
end

M.test_suite = unittest.TestSuite:new()
for _, case in ipairs(cases) do
  M.test_suite:add_test(function()
    local ok, err = pcall(run_case, case)
    return ok, err
  end, case.name)
end

return M
