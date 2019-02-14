-- HEAD --
-- Ref: https://www.exploit-db.com/exploits/42650
description = [[ 
Utilizing Docker via unprotected tcp socket (2375/tcp, maybe 2376/tcp),	an attacker can create a Docker container with the '/' path mounted with read/write permissions on the host server that is running the Docker container. 
As the Docker container executes command as uid 0 it is honored by the host operating system allowing the attacker to edit/create files owned by root. 
This exploit abuses this to creates a cron job in the '/etc/cron.d/' path of the host server. 
The Docker image should exist on the target system or be a valid image from hub.docker.com.

-- USE IT WITH -A
-- TO RUN AUTOMATICALLY, UPDATE DB : nmap --script-updatedb
		]]
-------------------------------------------------
----------- USE IT WHITH -A option --------------
-------------------------------------------------

author = "Vlad Rico"
categories = {"default","discovery", "safe", "version"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
dependencies = {"docker-version"}

local shortport = require "shortport"
local http = require "http"
local string = require "string"
local nmap = require "nmap"
local json = require "json"

-- RULE --
portrule = shortport.port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")

-- ACTION --
action = function(host,port)
  local result
  local opts = { header = {} }
  local ok_json

  opts['header']['Accept'] = 'application/json'
  opts['header']['Content-Type'] = 'application/json'
  result = http.get(host, port, "/containers/json",opts)
  
  if(result == nil) then
    return "GET request failed"
  end 
  
  if(result.rawheader == nil) then
    return "GET request didn't return a proper header."
  end 
  if(result.header['server'] and string.match(result.header['server'], 'Docker')) then
    port.version.extrainfo = "Target may be vulnerable to Docker API RCE via TCP socket unprotected"
    nmap.set_port_version(host, port)
    if(nmap.verbosity() > 2) then
      ok_json, result.body = json.parse(result.body)
      if(not(ok_json)) then result.body ="Error while parsing body" end
    else
      result.body = "Add option -vv to see full output" 
    end
    return result
  end

  port.version.extrainfo = 'Target not vulnerable'
  nmap.set_port_version(host,port)
  return result
end

