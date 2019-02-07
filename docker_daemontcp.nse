-- HEAD --
-- Ref: https://www.exploit-db.com/exploits/42650
description = [[ 
		Utilizing Docker via unprotected tcp socket (2375/tcp, maybe 2376/tcp),	an attacker can create a Docker container with the '/' path mounted with read/write permissions on the host server that is running the Docker container. 
		As the Docker container executes command as uid 0 it is honored by the host operating system allowing the attacker to edit/create files owned by root. 
		This exploit abuses this to creates a cron job in the '/etc/cron.d/' path of the host server. 
		The Docker image should exist on the target system or be a valid image from hub.docker.com.
		]]

author = "Vlad Rico"
categories = {"discovery", "safe", "version"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
dependencies = {"docker-version"}

local shortport = require "shortport"
local http = require "http"
local string = require "string"
local comm = require "comm"
local json = require "json"
local nmap = require "nmap"

-- RULE --
portrule = shortport.port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")

-- FUNCTIONS --
-- Try to patch raw data in correct json
local function jsonMonkeyPatch(data)
	local ok_json,res_json, tmp
	ok_json = false

	--> Need: "}]
	if(not(ok_json)) then
	tmp = data .. "DATA OMITTED\"}]"
	ok_json, res_json = json.parse(tmp)
	end

	--> Need: "]}]
	if(not(ok_json)) then
	tmp = data .. "DATA OMITTED\"]}]"
	ok_json, res_json = json.parse(tmp)
  	end

	--> Need: ":""}}}}] 
	if(not(ok_json)) then
	tmp = data .. "DATA OMITTED\":\"\"}}}}]"
	ok_json, res_json = json.parse(tmp)
	end
	
	-- Need: ":""}}]
	if(not(ok_json)) then
	tmp = data .. "DATA OMITTED\":\"\"}}]"
	ok_json, res_json = json.parse(tmp)
	end	

  	if(ok_json)then data = res_json end
	return data
end

--To parse raw response from SSL socket
local function parseSSLResult(result)
  local newres ={ header = {}, body="" }
  local ok_json, res_json
  local tmp

  --Parsing only with '-v' option
  if(nmap.verbosity() > 1) then
    -- Match the headers
    local headerString = result:match("[%g ]+\r\n([%g \r\n]+)\r\n\r\n") .. "\r\n"
    if headerString == nil then error("Couldn't find header") end

    -- Remove headers from initial result to only keep the body
    newres['body'] = result:gsub("[%g ]+" .. "\r\n", "")
    for k, v in headerString:gmatch("([%a%d%-]+): ([%g ]+)\r\n") do
	    if k == nil then error("Unparseable Header") end
	    newres['header'][k] = v
    end

    -- Try to parse body into json
    ok_json, res_json = json.parse(newres['body'])
    -- When there is too much data, nmap omits the end of the json data, so ... monkey patch
    if(not(ok_json))then
      newres['body'] = jsonMonkeyPatch(newres['body'])
    else
      newres['body'] = res_json
    end
	  
  else
	  newres['header'] = 'Enable verbose to see the output' 
  	  newres['body'] = 'Enable verbose to see the output'
  end
  return newres
end

-- ACTION --
action = function(host,port)
  local result
  local opts = { header = {} }
  local socket
  local correctOpt
  local earlyResp
  

  -- Without SSL Support
  opts['header']['Accept'] = 'application/json'
  opts['header']['Content-Type'] = 'application/json'
  result = http.get(host, port, "/containers/json",opts)
  
  if(result == nil) then
    return "GET request failed"
  end 
  
  if(result.rawheader == nil) then
    return "GET request didn't return a proper header. Maybe the server uses SSL on this port"
  end 
  if(result.header['server'] and string.match(result.header['server'], 'Docker')) then
    port.version.extrainfo = "Target may be vulnerable to Docker API RCE via TCP socket unprotected"
    nmap.set_port_version(host, port)
    return result
  end
  
  -- Force SSL request to access https://IP:port/containers/json
  opts['proto'] = 'ssl'

  socket, result, earlyResp = comm.opencon(host, port, "GET /containers/json HTTP/1.0\r\n\r\n",opts)
  
  if( not(socket) or not(result) ) then
      return 'GET request failed (with SSL)' 
  end
  result = parseSSLResult(result)
  if(string.match(result['header']['Server'],'Docker')) then
    port.version.extrainfo = "Target may be vulnerable to Docker API RCE via TCP socket unprotected"
    nmap.set_port_version(host, port)
    
    return result
  end
  nmap.port.version.extrainfo = 'Target not vulnerable'
  nmap.set_port_version(host,port)
  return 
end

