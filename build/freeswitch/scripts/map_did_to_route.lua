-- map_did_to_route.lua
-- Based on the FreeSWITCH freeswitch.Dbh example dialplan lookup pattern:
-- https://developer.signalwire.com/freeswitch/FreeSWITCH-Explained/Databases/Lua-FreeSWITCH-Dbh_3965358/

local raw_uri = ""
local dialed = ""
if session then
  raw_uri = session:getVariable("sip_invite_req_uri") or session:getVariable("sip_to_uri") or ""
  dialed = string.match(raw_uri, "sip:([^@>]*)") or session:getVariable("destination_number") or ""
else
  dialed = argv[1] or ""
end

if session and session:getVariable("lua_lookup_done") == "1" then
  freeswitch.consoleLog("DEBUG", "Lua SQLi demo skipping lookup on internally transferred call\n")
  return
end

local dbh = freeswitch.Dbh("sqlite://lua_sqli_demo")
assert(dbh:connected())

local matched = false
local function set_session_variables(row)
  if matched then
    return
  end
  matched = true
  for key, val in pairs(row) do
    if session then
      session:setVariable(key, tostring(val))
    end
    freeswitch.consoleLog("DEBUG", string.format("set(%s=%s)\n", key, tostring(val)))
  end
end

-- INTENTIONALLY VULNERABLE: This mirrors the unsafe freeswitch.Dbh example style.
-- The caller-controlled called SIP URI / destination number is concatenated directly into SQL.
local sql_query = "SELECT target AS route_target, scope AS route_scope FROM did_routes WHERE did = '" .. dialed .. "'"
freeswitch.consoleLog("INFO", string.format("Lua SQLi demo target raw_uri=%s dialed=%s\n", raw_uri, dialed))
freeswitch.consoleLog("INFO", string.format("Lua SQLi demo query: %s\n", sql_query))
assert(dbh:query(sql_query, set_session_variables))

if not matched and session then
  freeswitch.consoleLog("DEBUG", "set(route_target=<no-match>)\n")
end

dbh:release()
