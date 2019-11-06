
zniper  displays  TCP  connections seen by the first available interface, or the one specified with -i option.
The connections displayed can be reseted by injecting RST  packets  into  the  stream.  
Connections  initiated before zniper was started is also detected (unless -s option is used on the command line), 
these are displayed marked as 'Old' since the client sending the initial SYN packet is not known.


Claes M Nyberg <cmn@fuzzpoint.com>

Read the manual zniper.1 (or zniper.1.txt)
'make' to compile
'make install' to install binary and manual in /usr/local/zniper
'make uninstall' to uninstall binary and manual

Edit Makefile to change install directory.

// CMN
