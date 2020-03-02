# UrbanRain
Network scanner originally implemented as part of CSE 4471 at The Ohio State University. It is a command line interface which allows for host detection and port detection.

# Installation instructions:
- install Python (3.7 is recommended)
- clone the repo

# Useage instructions
- To run an unprivileged TCP connect scan, run
    - `python3 urban_rain.py -p <port_range> -sT <ip_address_range>`
- To run an unprivileged UDP connect scan, run
    - `python3 urban_rain.py -p <port_range> -sTU <ip_address_range>`
- To run an unprivileged PING  scan, run
    - `python3 urban_rain.py -p <port_range> -sTU <ip_address_range>`
- To get more help, run
    - `python3 urban_rain.py -h`
    or
    - `python3 urban_rain.py --help`
    
###### To-Do's 
- TODO: UPDATE WITH BEN'S COMMAND
- TODO: update calls above when they have been fixed to work without default port ranges
