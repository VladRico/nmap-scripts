-- HEAD --
description = [[ Utilizing Docker via unprotected tcp socket (2375/tcp, maybe 2376/tcp), an attacker can create a Docker container with the '/' path mounted with read/write permissions on the host server that is running the Docker container. As the Docker container executes command as uid 0 it is honored by the host operating system allowing the attacker to edit/create files owned by root. This exploit abuses this to creates a cron job in the '/etc/cron.d/' path of the host server. The Docker image should exist on the target system or be a valid image from hub.docker.com.]]

author = "Vlad Rico"
categories = {"discovery", "safe"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local shortport = require "shortport"
local http = require "http"
local string = require "string"

-- RULE --
portrule = shortport.port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")
-- ACTION --
action = function(host,port)
  local status = false
  local result
  local opts = { header = {} }
  opts['header']['Accept'] = 'application/json'
  opts['header']['Content-Type'] = 'application/json'

  result = http.get(host, port, "/containers/json",opts)
  request_type = "GET"
 
  if(result == nil) then
    return fail("GET request failed")
  end 

  if(result.rawheader == nil) then
    return fail("GET request didn't return a proper header")
  end 
  if(result.header['server'] and string.match(result.header['server'], 'Docker')) then
    return 'Target may be vulnerable to Docker API RCE via TCP socket unprotected'
  end

return 'Target not vulnerable'
end


