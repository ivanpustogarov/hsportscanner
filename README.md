This is a simple (and rather ad-hoc) port scanner for Tor hidden
services.  The scanner is a combination of a python script and two
patches for tor v0.2.2.37. Nmap and strobe did not work well for me.

There is a problem specific to Tor hidden services scanning. Assume that
we want to scan many ports but the hs_desc is not available.  This will
lead to many unnecessary thread/sockets_connections.  It is better to
try to connect to one port and check for the descriptor and then if it
is available, scan all other ports.

Files:

    hsportscanner.py -- The main program
    hiddservice-error-codes.tor-0.2.2.37.torpatch -- extends socks5 error codes.
                                                     Apply to Tor before running the scan.
    min-timeout-ms.tor-0.2.2.37.torpatch -- changes circuit timeouts to 1000 (magic number).
    socks.py -- Fixes some small bugs with parsing Socks5Error (lines 236 and 238). 
              Properly handles extending of error codes/messages.
    strobe.services -- ports in strobe format
    LICENSE -- MIT licence

Run Tor with --socksport at 127.0.0.1:9050 (default) before making a scan.

Examples:

    $ git clone https://git.torproject.org/tor.git
    $ cd tor
    $ git checkout tor-0.2.2.37
    $ git apply ../hiddservice-error-codes.tor-0.2.2.37.torpatch
    $ git apply ../min-timeout-ms.tor-0.2.2.37.torpatch
    $ ./autogen (you will need autotools)
    $ ./configure --disable-asciidoc (you will need libssl-dev and libevent-dev)
    $ make
    $ src/or/tor
    
    $ ./hsportscanner.py -h torwikignoueupfm.onion -p 80,443
    $ ./hsportscanner.py -h torwikignoueupfm.onion -p 80-84,443,500-502
    $ ./hsportscanner.py -h torwikignoueupfm.onion -S strobe.services
    $ ./hsportscanner.py -h torwikignoueupfm.onion -S strobe.services -o output1.txt,output2.txt,-


Results can be:

    DESC_UNAVAILABLE/NO_INTROS -- there was no HS descriptor or introduction
                                  points were unreachable.
    CANT_ATTACH/TTL_EXPIRED    -- Normally it means that the circuit to either
                                  the hidden service or responsisble hidden
				  service directories could not be established
				  by Tor. Repeat the scan.
    DESC_HERE/PORT_CLOSED      -- we successfully downloaded the HS descriptor
                                  and connected to the hidden service, the prob
				  ed port was closed. 
    DESC_HERE/PORT_FILTERED    -- we successfully downloaded the HS descriptor
                                  and connected to the hidden service, the
				  probed port might be open.
    CONN_FAILED/UKNOWN_REASON  -- means that we downloaded the desc and tried
                                  to establish rend and intro circuit, but the
				  connection failed. Repeat the scan.
    DESC_HERE/OPEN             -- we successfully downloaded the HS descriptor
                                  and connected to the hidden service, the
				  probed port is open.

BC:14iyH71Y9kEDUXdQCytizPNTvFNAUUn3do 
