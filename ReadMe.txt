
Author: Claes M Nyberg <cmn@fuzzpoint.com>
When: 2003


-=[ What is this?
zniper  displays  TCP  connections seen by the first available interface, or the one specified with -i option.
The connections displayed can be reseted by injecting RST  packets  into  the  stream.  
Connections  initiated before zniper was started is also detected (unless -s option is used on the command line), 
these are displayed marked as 'Old' since the client sending the initial SYN packet is not known.

-=[ Building
Edit Makefile to change install directory and run:
'make' to compile
'make install' to install binary and manual in /usr/local/zniper
'make uninstall' to uninstall binary and manual


-=[ Usage
Read the manual zniper.1 (or zniper.1.txt) or run './zniper -h'.
$ ./zniper -h

Zniper - <cmn@fuzzpoint.com>
Usage: ./zniper [Option(s)]

 Options:
  -b color   - Background color
  -B color   - Border color
  -f color   - Foreground color
  -h         - This help
  -i iface   - Network interface
  -l file    - Log status information to file
  -n         - Do not attempt to resolve hostnames
  -p         - Do not put the interface in promiscuous mode
  -s         - Require the initial SYN packet to display a connection
  -v         - Verbose output, repeat to increase
  -V         - Print "1.0" and exit

-=[ Example
# ./zniper -i enp5s0

Have fun!
// CMN
