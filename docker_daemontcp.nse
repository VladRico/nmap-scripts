-- HEAD --
-- Ref: https://www.exploit-db.com/exploits/42650
description = [[ Utilizing Docker via unprotected tcp socket (2375/tcp, maybe 2376/tcp), an attacker can create a Docker container with the '/' path mounted with read/write permissions on the host server that is running the Docker container. As the Docker container executes command as uid 0 it is honored by the host operating system allowing the attacker to edit/create files owned by root. This exploit abuses this to creates a cron job in the '/etc/cron.d/' path of the host server. The Docker image should exist on the target system or be a valid image from hub.docker.com.]]

author = "Vlad Rico"
categories = {"discovery", "safe", "version"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local shortport = require "shortport"
local http = require "http"
local string = require "string"
local comm = require "comm"
local json = require "json"

local function parseSSLResult(result)
  local newres ={ header = {}, body="" }
  local headerString = result:match("[%g ]+\r\n([%g \r\n]+)\r\n\r\n") .. "\r\n"
  if headerString == nil then error("Couldn't find header") end
  for k, v in headerString:gmatch("([%a%d%-]+): ([%g ]+)\r\n") do
	  if k == nil then error("Unparseable Header") end
	  newres['header'][k] = v
	  newres['body'] = result.gsub(result,newres['header'][k], "")
	  print(result.gsub(result,newres['header'][k], ""))
  end
  --newres['body'] = json.parse(result)
  return newres
end

-- RULE --
portrule = shortport.port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")

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
    port.version.name = 'docker'
    port.version.product = "Docker"
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
  --if(string.match(result,'Docker')) then
    local newres
    port.version.name = 'docker'
    port.version.product = "Docker"
    port.version.extrainfo = "Target may be vulnerable to Docker API RCE via TCP socket unprotected"
    nmap.set_port_version(host, port)
    
    return result
  end
  nmap.port.version.extrainfo = 'Target not vulnerable'
  return 'Target not vulnerable'
end

