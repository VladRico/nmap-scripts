# nmap-scripts
useful (maybe ?) scripts for nmap

# Content
- ~~docker_daemontcp : Check if port 2375 and 2376 are running docker API instance, and if the API socket is unprotected~~
  ~~Add -vv to see the full output~~

- httpcs_docker-daemontcp-prod.nse : MUST BE RUN WITH -A. You could update nmap database with "nmap --script-updatedb". Then, the script will be automatically run with -A  

# TODO : 
- docker_daemontcp : run exploit if vulnerable
