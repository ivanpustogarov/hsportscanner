#! /usr/bin/python

# Copyright (c) 2013-2014 Ivan Pustogarov
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import socket
import socks
import threading
import sys
from time import time,sleep
import os
import subprocess

TOR_SOCKS_IP_ADDRESS = "127.0.0.1"
TOR_SOCKS_PORT       = 9050
ONION_ADDR_Z_LENGTH = 16 # lenght of onion address without ".onion" part
MAX_FAILED_CONNS = 1 # MEANS we will try to connect 2 times
MAX_PORTCONNECT_PER_TRY = 3 # how many tries we should make for a port until returns success or "not allowed by ruleset" 

############ CONNECTION STATES ################
CONN_STATE_UNTRIED                 = 0 # We did not try to connect to a hidden service at all.
CONN_STATE_IS_BEING_CHECKED        = 1 # The desc is being tried. We go to this state in order
                                       # to avoid launching serveral desc checks in parallel.
CONN_STATE_DESC_UNAVAILABLE        = 2 # We tried to connect and got error code 10 from the socks5.
CONN_STATE_DESC_AVAILABLE          = 3 # We were connecting to a hidden service and either
                                       # got a reply from the server or got error
    		                       # "could not attach circuit". Both cases mean
    		                       # that we downloaded the desciptor.
CONN_STATE_TIMEDOUT                = 4 # We were connecting to a hidden service and got either
                                       # cannot_attach or ttl_timeout, which basically means
    			               # that tor tried to find a circuit for 2 mins and failed.
CONN_STATE_CONNECTED               = 5
CONN_STATE_FAILED_REASON_UNKNOWN   = 6
CONN_STATE_FINISHED                = 7 # The scan is finished either successfully or not.

############ LOCKS ################
OUTPUT_LOCK = threading.Lock()
LISTS_LOCK = threading.Lock()

######## LOG LEVELS ######
CURRENT_LOG_FDS   = [sys.stdout] # file descriptors where we write our log messages to
LOG_NOTICE  = 0
LOG_INFO    = 1
LOG_DEBUG   = 2
CURRENT_LOG_LEVEL = LOG_DEBUG

######## SOCKS ERROR CODES #####
SOCKS_CANT_ATTACH          = 1
SOCKS_REFUSED_CONN_BY_RULE = 2
SOCKS_REFUSED_CONN_REMOTE  = 5
SOCKS_TTL_EXPIRED          = 6
SOCKS_DESC_UNAVAILABLE     = 10
SOCKS_TOR_MISC             = 12


######## WGET CRAWL #####
DO_CRAWL = None 
os.environ['TORSOCKS_DEBUG']="-1"
WGET_CMD=["torsocks", "wget",\
"--tries=2", \
"--timestamping", \
"--wait=2", \
"--timeout=120", \
"--random-wait", \
"--recursive", \
"--no-parent", \
"--reject", "*.jpg", "--reject", "*.gif", \
"--reject", "*.png", "--reject", "*.css", \
"--reject", "*.pdf", "--reject", "*.bz2", \
"--reject", "*.gz", "--reject", "*.zip", \
"--reject", "*.mov", "--reject", "*.fla", \
"--reject", "*.xml", \
"--reject", "*.tar", "--reject", "*.rar", \
"--reject", "*.JPG", "--reject", "*.GIF", \
"--reject", "*.PNG", "--reject", "*.CSS", \
"--reject", "*.PDF", "--reject", "*.BZ2", \
"--reject", "*.GZ", "--reject", "*.ZIP", \
"--reject", "*.MOV", "--reject", "*.FLA", \
"--reject", "*.XML", \
"--reject", "*.js", \
"--reject", "*.TAR", "--reject", "*.RAR", \
"--reject", "*.avi", "--reject", "*.AVI", \
"--no-check-certificate", \
"--force-directories", \
"--follow-ftp", \
"--convert-links", \
#"--no-remove-listing", \
"-U", "\"Mozilla/5.0 (compatible; Konqueror/3.2; Linux)\"", \
"-Q2m"]



######## CLASSES #####

## Parse and keep parameters provided from the command line
#
#  This class has functionality similar to Python's argparse but 
#  includes some additional functions to parse comman line parameters.
#  TODO: migrate to argparse
class ConfigParams:
 
    hosts_filename = None # Contains onion addresses to scan. may contain ports to scan (space seperated)
    hid_servs_to_scan_dict = dict() # contains HiddenService objects
    ports_filename = None # Contains  ports to scan (-S option) in strobe format
    ports_to_scan = list() # This is a list of ports indicated by -p command line argument, from
                           # <ports_filename> file
    ports_to_scan_per_host = dict() # This is a dict of lists. Each list corresponds
                                    # to a host. We use it if the input file containted
				    # ports for a give host
    max_num_of_threads = 64 # Maximum number of threads per onion address

    # If -m=max_num_of_hs_scanned_in_parallel is set it means
    # that you will have n*m threads in total
    max_num_of_hs_scanned_in_parallel = 1
    hosts_start_line = 0
    hosts_num_lines = -1 
    do_crawl = False


    ## Check if a string has an onion address
    #
    #  @param self The object pointer.
    #  @param address Address to chekc. Type: string.
    #  @return True, if the address is an onion addres, False otherwise
    def is_onion_address(self,address):
        if not(".onion" in address):
	    return False
	ndx = address.index('.onion')
	z = address[:ndx]
	if len(z) != ONION_ADDR_Z_LENGTH:
	    return False
	return True
	    
    ## Parse line "z.onion p1 p2 p3 ...", and updated corresponding object in <hid_servs_to_scan_dict> for an onion address
    #
    #  @param self The object pointer.
    #  @param onion_address_and_ports A space-separated list of an onion address and ports
    #                                 The caller should guarantee that an element with
    #                                 onion address was created in self.hid_servs_to_scan_dict. Type: string
    #  @return 0 if all ports had positive values, 1 otherwise
    def add_ports_per_host(self,onion_address_and_ports):
	onion_address = onion_address_and_ports[0]
        ports_str = onion_address_and_ports[1:]
	ports_int = list()
	for port_str in ports_str:
	    ports_int.append(int(port_str)) 
	ports_int.sort()
	if ports_int[-1] < 0:
	    thdprint(LOG_NOTICE,"Input file has {0}, which has just one negative port. Bug. Exiting.".format(onion_address))
	    exit()
	# if the scanned interrupted at port 2, don't bother about creating a new list.
	# we will re-scan the host completely
	if (ports_int[0] < 0) and (abs(ports_int[0]) <= 2):
	    return 1

        # TODO: We should not have more than tow negative ports, add a check.
	# We can have several negative ports -- assume we
	# did two scans and they were interruped at different ports.
	if (ports_int[0] < 0):
	    max_port_tried = abs(ports_int[0])
            ports_int.pop(0) 
	    ports_int.extend(range(max_port_tried,65536))
        if (self.hid_servs_to_scan_dict[onion_address].ports_to_scan == None):
	    self.hid_servs_to_scan_dict[onion_address].ports_to_scan = ports_int
	    thdprint(LOG_DEBUG,"Initializing ports for {}:{}".format(onion_address,ports_int))
	else:
	    self.hid_servs_to_scan_dict[onion_address].ports_to_scan.extend(ports_int)
	    thdprint(LOG_DEBUG,"Extending ports for {}:{}+{}".format(onion_address,self.hid_servs_to_scan_dict[onion_address].ports_to_scan,ports_int))
        self.hid_servs_to_scan_dict[onion_address].ports_to_scan = list(set(self.hid_servs_to_scan_dict[onion_address].ports_to_scan)) 
        self.hid_servs_to_scan_dict[onion_address].ports_to_scan.sort()
	#print "Updated ports for {}:{}".format(onion_address,self.hid_servs_to_scan_dict[onion_address].ports_to_scan)
	return 0

    ## Read file which contains "z.onion p1 p2 p3..." per line,
    #  create the corresponding HiddenService object and populate it
    #  with ports to scan.
    # 
    #  @param self The object pointer.
    #  @param filename Filename to read. Type: string
    #  @return 0 if everything is alreight, -1 if the file could not be open
    def add_hosts_from_file(self,filename):
        try:
            fd = open(filename,"rt")
	except IOError:
            print "Could not open file with hosts to scan!"
            return -1 
        line = fd.readline()
	num_of_read_lines = 1
	current_line_number = 0 # start count lines from 0 
        while line:
	    # If the user instructed to skip some first lines
	    if current_line_number < self.hosts_start_line:
                line = fd.readline()
	        current_line_number += 1
		continue
	    # If the user instructed not to read final lines
	    if (self.hosts_num_lines != -1) and (num_of_read_lines > self.hosts_num_lines):
	        break
	    # The format of the file is z.onion p1 p2 p3 p4 ... pn
	    onion_address_and_ports = line.strip().split(' ')
	    onion_address = onion_address_and_ports[0] 

	    if self.is_onion_address(onion_address) and (not(onion_address in self.hid_servs_to_scan_dict)):
                self.hid_servs_to_scan_dict[onion_address] = HiddenService(onion_address)
		if(len(onion_address_and_ports) > 1): # if has ports list
		    self.add_ports_per_host(onion_address_and_ports)
            elif (self.is_onion_address(onion_address)):
	        #thdprint(LOG_NOTICE,"Input file has {0}, which already in the list for scanning. Skipping (but will add new ports if any).".format(onion_address))
		if(len(onion_address_and_ports) > 1): # if has ports list
		    self.add_ports_per_host(onion_address_and_ports)
	    else:
	        thdprint(LOG_NOTICE,"Input file has \"{}\", which does not look like an onion address. Skipping.".format(onion_address))

            line = fd.readline()
	    num_of_read_lines += 1
	    current_line_number += 1
        fd.close()
	return 0

    ## Parse a line with onion addresses and create corresponding HiddenService objects
    # 
    #  @param self The object pointer.
    #  @param hosts_csv Line of the form z.onion1[,z.onion,[... ]]. Type: string
    #  @return 0
    def add_hosts_from_command_line(self,hosts_csv):
        potential_addresses_list = hosts_csv.split(',')
	for address in potential_addresses_list:
	    if self.is_onion_address(address) and (not(address in self.hid_servs_to_scan_dict)):
                self.hid_servs_to_scan_dict[address] = HiddenService(address)
            elif (self.is_onion_address(address)):
	        thdprint(LOG_NOTICE,"{0} Already in the list for scanning. Skipping (but will add new ports if any).".format(address))
	    else:
	        thdprint(LOG_NOTICE,"{0} does not look like an onion address. Skipping.".format(address))
        return 0

    ## Parse a strobe.services formatted file and add ports to scan
    # 
    #  @param self The object pointer.
    #  @param filename Filename to read, should be formateed as strobe.services. Type: string
    #  @return 0 if everything is alright, -1 if a file could not be open
    def add_ports_from_file(self,filename):
        try:
            fd = open(filename,"rt")
	except IOError:
            print "Could not open file with hosts to scan!"
            return -1 
	line = "init"
        while line:
            line = fd.readline().lstrip()
	    if not(line):
	        break
	    if line[0] == '#': # If a comment line
	        continue
	    portnumstr_proto = line.split()[1]
	    [portnumstr,proto] = portnumstr_proto.split('/')
	    if (proto == "tcp"):
	        #thdprint(LOG_DEBUG,"Adding port {0} from the service file".format(portnumstr_proto))
	        portnum = int(portnumstr)
		if (portnum > 0) and (portnum < 2**16):
	            self.ports_to_scan.append(int(portnum))
        self.ports_to_scan = list(set(self.ports_to_scan)) 
        self.ports_to_scan.sort()
	return 0


    ## Parse ports provided from the command line
    # 
    #  @param self The object pointer.
    #  @param ports_csv is a line of the form 4-8,10,20-100. Type: string
    #  @return 0
    def add_ports_from_command_line(self,ports_csv):
        port_ranges_list = ports_csv.split(',')
	for port_range in port_ranges_list:
	    if '-' in port_range:
	        ndx = port_range.index('-')
	        port_b = int(port_range[:ndx]) # Stangs for port begin
	        port_e = int(port_range[ndx+1:]) # Stangs for port end 
		self.ports_to_scan.extend(range(port_b,port_e+1))
	    else:
	        self.ports_to_scan.append(int(port_range))
	# Let's remove dublicates
        self.ports_to_scan = list(set(self.ports_to_scan)) 
        self.ports_to_scan.sort()
        return 0

    ## Open files where the output will go and save corresponding file descriptors
    # 
    #  @param self The object pointer.
    #  @param filenames Comma-separeted filenames. Type: string
    #  @return 0
    def add_current_log_fds(self,filenames):
	global CURRENT_LOG_FDS
        filenames = list(set(filenames)) 
        # stdout is by default in the list
	# so we need to remove it if it is not in the command line
	if not("-" in filenames):
	    CURRENT_LOG_FDS = list()
	else:
	    filenames.remove("-")
        for filename in filenames:
            try:
                fd = open(filename,"wt")
	        CURRENT_LOG_FDS.append(fd)
            except IOError:
                thdprint(LOG_NOTICE,"Could not open log file {}.".format(filename))
        if len(CURRENT_LOG_FDS) == 0:
            thdprint(LOG_NOTICE,"All log files specified are not usable. Will use stdout.".format(filename))
            CURRENT_LOG_FDS = [sys.stdout] 
	return 0

    ## Parse command line arguments
    #
    #  @param self The object pointer
    #  @param arg_list List containing comman line arguments. Type: list
    #  @return 0
    def init_from_command_line(self,arg_list):
        global CURRENT_LOG_LEVEL
	global CURRENT_LOG_FDS
	global DO_CRAWL

        if ("--help" in arg_list): # print help 
	    print "Scan Tor Hidden services for open ports and optionally make crawling\n"
	    self.print_usage_and_exit()

        if ("-d" in arg_list): # print help 
	    try:
                CURRENT_LOG_LEVEL = int(arg_list.pop(arg_list.index("-d")+1))
            except IndexError as e:
                print "hsportscanner.py: -d requires an argument, try '--help' for more information."
		exit(0)
	    if (CURRENT_LOG_LEVEL < LOG_NOTICE) or (CURRENT_LOG_LEVEL > LOG_DEBUG):
	        print "Failed to parse log_level."
    	        self.print_usage_and_exit()
            #print "Debug level is {}".format(CURRENT_LOG_LEVEL)
            arg_list.remove("-d")

        if ("-o" in arg_list): # print help 
	    try:
                filenames = arg_list.pop(arg_list.index("-o")+1).split(',')
            except IndexError as e:
                print "hsportscanner.py: -o requires an argument, try '--help' for more information."
		exit(0)
	    self.add_current_log_fds(filenames)
            arg_list.remove("-o")

        if ("-p" in arg_list): 
	    try:
                self.add_ports_from_command_line(arg_list.pop(arg_list.index("-p")+1))
            except IndexError as e:
                print "hsportscanner.py: -p requires an argument, try '--help' for more information."
		exit(0)
            arg_list.remove("-p")

        if ("-S" in arg_list): 
	    try:
                self.add_ports_from_file(arg_list.pop(arg_list.index("-S")+1))
            except IndexError as e:
                print "hsportscanner.py: -S requires an argument, try '--help' for more information."
		exit(0)
            arg_list.remove("-S")

        if ("-n" in arg_list): 
	    try:
                self.max_num_of_threads = int(arg_list.pop(arg_list.index("-n")+1))
            except IndexError as e:
                print "hsportscanner.py: -n requires an argument, try '--help' for more information."
		exit(0)
            arg_list.remove("-n")

        if ("-m" in arg_list): 
	    try:
                self.max_num_of_hs_scanned_in_parallel = int(arg_list.pop(arg_list.index("-m")+1))
            except IndexError as e:
                print "hsportscanner.py: -m requires an argument, try '--help' for more information."
		exit(0)
            arg_list.remove("-m")

        if ("--hosts-start-line" in arg_list): 
	    try:
                self.hosts_start_line = int(arg_list.pop(arg_list.index("--hosts-start-line")+1))
            except IndexError as e:
                print "hsportscanner.py: --hosts-line-line requires an argument, try '--help' for more information."
		exit(0)
            arg_list.remove("--hosts-start-line")

        if ("--hosts-num-lines" in arg_list): 
	    try:
                self.hosts_num_lines = int(arg_list.pop(arg_list.index("--hosts-num-lines")+1))
            except IndexError as e:
                print "hsportscanner.py: --hosts-num-lines requires an argument, try '--help' for more information."
		exit(0)
            arg_list.remove("--hosts-num-lines")

        if ("--do-crawl" in arg_list): 
            self.do_crawl = arg_list.pop(arg_list.index("--do-crawl")+1)
	    DO_CRAWL = self.do_crawl 
            WGET_CMD.append("--directory-prefix={0}".format(self.do_crawl))
            arg_list.remove("--do-crawl")

        if ("-i" in arg_list): 
	    try:
                self.hosts_filename = arg_list.pop(arg_list.index("-i")+1)
            except IndexError as e:
                print "hsportscanner.py: -i requires an argument, try '--help' for more information."
		exit(0)
	    self.add_hosts_from_file(self.hosts_filename)
            arg_list.remove("-i")

        if ("-h" in arg_list): 
	    try:
                hosts = arg_list.pop(arg_list.index("-h")+1)
            except IndexError as e:
                print "hsportscanner.py: -h requires an argument, try '--help' for more information."
		exit(0)
            self.add_hosts_from_command_line(hosts)
            arg_list.remove("-h")
        
        if len(arg_list) > 1:
            print "Unknown params: {0}".format(arg_list[1:])
    	    self.print_usage_and_exit()

        if len(self.hid_servs_to_scan_dict) == 0:
            print "No hosts to scan were specified. Use -h or -i."
    	    self.print_usage_and_exit()

        if len(self.ports_to_scan) == 0:
	    self.ports_to_scan.extend([22,80,443])

	return 0


    def print_usage_and_exit(self):  
        print """Usage: hsportscanner.py
                               [-h z.onion[,z.onion,[... ]]] 
			       [-p ports_to_scan (e.g. \"-p 2-5,80,50-134, default: 22,80,443)\"]
			       [-n max_num_of_threads_per_host(64 by default)]
			       [-m max_num_of_hs_scanned_in_parallel(1 by default)]
	                       [-i hosts_filename ('z.onion p1 p2 p3 p4 ... pn' per line)]
	                       [-S services_filename(strobe format)]
    			       [--help]
    			       [--do-crawl (to crawl open ports with torsocks wget)]
    			       [-d log_level(0,1,2; default is 2 (DEBUG))]
    			       [-o log_filename (stdout by default)]
    			       [--hosts-start-line NUM (default 0, i.e. from start)]
    			       [--hosts-num-lines  NUM (default -1, i.e. whole file)]
    			       [--help]"""
	#print "Possible schedule types are: {0}".format(self.SCHEDULE_TYPES)
	print
	print "   Hosts specified by -h will be scanned first."
	print "   Input file should contain one onion address per line in form <z>.onion p1 p2 p3 ..."
	print "   In case ports are indicated, ports from the command line will be ignored"
	print "   If a negative port is indicated then all ports from this port till 65535 will be tried"
	print "    for this onion address\n"
        print "   Log levels: 0 -- show only open ports."
        print "               1 -- show open and closed ports."
        print "               2 -- show open and closed ports, debug messages."
	print "   If -m is set then you will have up to n*m threads."
	print "   Output can go to different files. E.g.: \"-o filename1,-\" for filename1 and stdout."
    	print "   --hosts-start-line allows to start reading the file with hosts from line NUM,"
	print "                                                starts from 0 (and NOT from 1)" 
    	print "   --hosts-num-lines allows to read only NUM lines from file with hosts" 
        exit()
    

## Keeps the current state of a hidden service to scan.
#
# Contains onion address, connection state (e.g. decriptor is ready, failed. etc),
# next index in the global list of ports to scan.
class HiddenService:

    def __init__(self,onion_address):
        self.onion_address = onion_address # in the form <z>.onion
	self.connect_state = CONN_STATE_UNTRIED
	self.failed_connect_tries = 0 # number of connections to a hidden services which ended with
	                              # cant_attach/ttl_timeout/desc_anavailable. But once we
				      # connected reset the counter to zero.
	self.scan_is_started = False 
	self.next_port_ndx_to_scan = 0
	self.scan_is_finished = False 
	self.ports_to_scan = None # This becomes None if the input file has ports to scan for
	                          # this onion address. Otherwise this field remains
				  # None and the ports provided from the command line will
				  # be used.

######## GLOBAL FUNCTIONS #####

## Convert log-level from integer to string
#
#  @param log_level Log level to convert. Type: int
#  @return The string representation of the log level
def log_level_to_str(log_level):
    if log_level == 0:
        return "notice"
    elif log_level == 1:
        return "info"
    elif log_level == 2:
        return "debug"
    return "loglevel-{}".format(log_level)

## Thread safe prinining to open file descriptor (can be sys.stdout) 
#  Supports debug levels
#
#  @param log_level Log level of the message. Type: int
#  @param message Message to print to all output files
#  @return 0
def thdprint(log_level,message):
    OUTPUT_LOCK.acquire()
    if CURRENT_LOG_LEVEL >= log_level:
        for log_fd in CURRENT_LOG_FDS:
            log_fd.write("{0} [{1}] : {2}\n".format(str(time()),\
	                   log_level_to_str(log_level),message))
	    log_fd.flush()
    OUTPUT_LOCK.release()
    return 0


## Checks the number of non-finished threads for
#  the current process and go into an infinite loop
#  until only the main thread is left
#  sleeps for 5 seconds between each check
#
#  @return 0 
def wait_nonmain_threads_dead():
    time1 = time()
    time2 = time()
    while True:
        threads = threading.enumerate()
        num_of_alive = 0
        for thread in threads:
            if thread.is_alive():
                num_of_alive += 1  
        if num_of_alive == 1: # Only main thread is left
            break
	#sleep(5)
        time2 = time()
        if time2-time1 > 10:
            time1 = time()
            print "We're waiting for {0} scans!".format(num_of_alive-1)
    return 0

## Checks the number of non-finished threads which contain a specific string in their names.
#
#  @param fltr Count only treads which have this string in their names. Type: string
#  @return Number of running threads
def get_num_of_alive_threads(fltr = ""):
    threads = threading.enumerate()
    num_of_alive = 0
    for thread in threads:
        if thread.is_alive() and (fltr in thread.name):
	    #print thread.name
            num_of_alive += 1  
    return num_of_alive

## Thread-safe append to list.
#
#  @param el Element to append. Type: any
#  @return 0
def thappend(lst,el):
    LISTS_LOCK.acquire()
    lst.append(el)
    LISTS_LOCK.release()
    return 0

## Thread-safe remove from list. The caller should guardantee that the removed element
#  is in the list.
#
#  @param el Element to remove. Type: any
#  @return 0
def thremove(lst,el):
    LISTS_LOCK.acquire()
    lst.remove(el)
    LISTS_LOCK.release()
    return 0

## Thread-safe pop from list. The caller should guardantee that the removed element
#  is in the list.
#
#  @param el Element to pop. Type: any
#  @return 0
def thpop(lst,i):
    LISTS_LOCK.acquire()
    el = lst.pop(i)
    LISTS_LOCK.release()
    return el 

##  Print a message and change the scanning state of a HiddenService object based on the error value,
#
#  @param hid_serv Hidden service for which to change the state. Type: class HiddenService
#  @param e Socks5 error. Type: class socks.Socks5Error
#  @return 0
def process_soccks5_error(hid_serv,port_ndx,e):
    hostname = hid_serv.onion_address
    port = hid_serv.ports_to_scan[port_ndx]
    if e.value[0] == SOCKS_DESC_UNAVAILABLE:
        hid_serv.connect_state = CONN_STATE_DESC_UNAVAILABLE
        #hid_serv.failed_connect_tries += 1
        thdprint(LOG_NOTICE,"{0}:{1} DESC_UNAVAILABLE/NO_INTROS; {2}".format(hostname,port,e.value))

    elif e.value[0] == SOCKS_CANT_ATTACH or e.value[0] == SOCKS_TTL_EXPIRED:
        hid_serv.connect_state = CONN_STATE_TIMEDOUT
        #hid_serv.failed_connect_tries += 1
        thdprint(LOG_INFO,"{0}:{1} CANT_ATTACH/TTL_EXPIRED; {2}".format(hostname,port,e.value))

    elif (e.value[0] in [SOCKS_REFUSED_CONN_BY_RULE,SOCKS_REFUSED_CONN_REMOTE]): # means we connected and the port is closed
        hid_serv.failed_connect_tries = 0  # reset failed tried counter
	if port_ndx >= hid_serv.next_port_ndx_to_scan:
            hid_serv.next_port_ndx_to_scan = (port_ndx+1)
        hid_serv.connect_state = CONN_STATE_CONNECTED
        thdprint(LOG_INFO,"{0}:{1} DESC_HERE/PORT_CLOSED {2}".format(hostname,port,e.value))

    elif (e.value[0] == SOCKS_TOR_MISC): # also means that we connected.
        hid_serv.failed_connect_tries = 0  # reset failed tried counter
	if port_ndx >= hid_serv.next_port_ndx_to_scan:
            hid_serv.next_port_ndx_to_scan = (port_ndx+1)
        hid_serv.connect_state = CONN_STATE_CONNECTED
        thdprint(LOG_INFO,"{0}:{1} DESC_HERE/PORT_FILTERED {2}".format(hostname,port,e.value))

    else: # means that we downloaded the desc and tried to establish rend and intro circuit
        hid_serv.connect_state = CONN_STATE_FAILED_REASON_UNKNOWN
        #hid_serv.failed_connect_tries += 1
        thdprint(LOG_INFO,"{0}:{1} CONN_FAILED/UKNOWN_REASON {2}".format(hostname,port,e.value))
    return 0

## Run wget for for onion address in case --crawl-open-ports was specified in the command line.
#  See wget paramters at the beginning of this file
# 
#  @param port Make wget to connect to this port
#  @return 0
def run_crawl(hostname,port):
    global DO_CRAWL
    if DO_CRAWL == None:
        thdprint(LOG_DEBUG,"{0}:{1} Will not crawl".format(hostname,port))
        return 0

    thdprint(LOG_NOTICE,"{0}:{1} Crawling (log to {2}/{0}.{1}.wgetlog).".format(hostname,port,DO_CRAWL))
    fd = open("{0}/{1}.{2}.wgetlog".format(DO_CRAWL,hostname,port),"at")

    wget_command = list(WGET_CMD)
    wget_command.append("{0}:{1}".format(hostname,port))
    subprocess.call(wget_command,stdout=fd,stderr=fd)

    wget_command = list(WGET_CMD)
    wget_command.append("https://{0}:{1}".format(hostname,port))
    subprocess.call(wget_command,stdout=fd,stderr=fd)

    thdprint(LOG_NOTICE,"{0}:{1} Finished crawling.".format(hostname,port))
    fd.close()
    return 0
    
## Try to connect to a hidden service through Tor's Socks port
#
#  IMPORTANT: the caller should guarantee that no other thread
#  is working with the object's .connect_state field
#
#  @param hid_serv Hidden service to connect. Type: class HiddenService.
#  @param port_ndx Index in the list of ports to scan for the hidden service.
#                  Connection will be established to this port. Type: int
#  @param hid_serv_lock Lock for the HiddenService object. Type: class Threading.Lock()   
#  @param fin_sem
#  @param fin_event.
#  @param num_of_tries Try to connect this number of times. Type: int
#  @return 0
def make_connect(hid_serv,port_ndx,hid_serv_lock,fin_sem = None,fin_event = None,num_of_tries = MAX_PORTCONNECT_PER_TRY):
    port = hid_serv.ports_to_scan[port_ndx]
    hostname = hid_serv.onion_address
    #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for i in range(num_of_tries):
        try:
            thdprint(LOG_DEBUG,"Checking {0}:{1} (try {2})".format(hostname,port,i+1))
            s = socks.socksocket()
            s.setproxy(socks.PROXY_TYPE_SOCKS5,TOR_SOCKS_IP_ADDRESS,TOR_SOCKS_PORT)
            s.connect((hostname,port))
	    s.close()
            hid_serv.failed_connect_tries = 0  # reset failed tried counter
	    if port_ndx >= hid_serv.next_port_ndx_to_scan:
	        if port_ndx < len(hid_serv.ports_to_scan):
                    hid_serv.next_port_ndx_to_scan = (port_ndx+1)
		else:
                    hid_serv.next_port_ndx_to_scan = len(hid_serv.ports_to_scan)-1
            thdprint(LOG_NOTICE,"{0}:{1} DESC_HERE/OPEN".format(hostname,port))
	    run_crawl(hostname,port)
            hid_serv.connect_state = CONN_STATE_CONNECTED
	    break
        except socks.Socks5Error as e:
            hid_serv_lock.acquire()
            process_soccks5_error(hid_serv,port_ndx,e)
            hid_serv_lock.release()
	    s.close()
            if (e.value[0] in [SOCKS_REFUSED_CONN_BY_RULE,SOCKS_REFUSED_CONN_REMOTE,SOCKS_DESC_UNAVAILABLE,SOCKS_TOR_MISC]):
	        break
	    elif (i == (num_of_tries-1)):
                thdprint(LOG_DEBUG,"Final try (#{0}) for {1}:{2} unsuccessful.".format(i+1,hostname,port))
    if fin_sem:
        fin_sem.release()
    if fin_event:
        fin_event.set()
    return 0

## Check if a hidden service is reachable 
#
#  Before we start the scanning for all ports we need to check if the HS descriptor is available,
#  and we can scan at least one port
#
#  @param hid_serv Hidden service to check Type: class HiddenService.
#  @param state_changed_event This event will be triggered if the state of the hidden service is changed. Type: threading.Event().
#  @return 0
def check_host(hid_serv,state_changed_event):
    adr = hid_serv.onion_address
    ndx = hid_serv.next_port_ndx_to_scan + hid_serv.failed_connect_tries
    #print "ndx=",ndx
    if ndx >=len(hid_serv.ports_to_scan):
        port = hid_serv.ports_to_scan[-1]
	ndx = len(hid_serv.ports_to_scan) - 1
    else:
        port = hid_serv.ports_to_scan[ndx]
    thdprint(LOG_DEBUG,"Checking connectivity for {0}. Port used is {1}.".format(adr,port))
    hid_serv_lock = threading.Lock()
    make_connect(hid_serv,ndx,hid_serv_lock,None,None,5)
    if hid_serv.failed_connect_tries >= MAX_FAILED_CONNS:
        thdprint(LOG_DEBUG,"Tried to connect to {0} for {1} times. Port tried is {2}. Give up.".format(adr,MAX_FAILED_CONNS+1,port))
        hid_serv.connect_state = CONN_STATE_FINISHED
    elif hid_serv.connect_state != CONN_STATE_CONNECTED:
        hid_serv.failed_connect_tries += 1 
        thdprint(LOG_DEBUG,"Tried to connect to {0} for {1} times. Port tried is {2}. Will try more.".format(adr,hid_serv.failed_connect_tries,port))
        hid_serv.connect_state = CONN_STATE_UNTRIED 
    else:
        thdprint(LOG_DEBUG,"Connected to {0} from {1} attempt. Port tried is {2}.".format(adr,hid_serv.failed_connect_tries+1,port))
    state_changed_event.set()
    #print "Conncectivity checked"
    return 0

##  Scan a hidden service for open ports
#
#  @param hid_serv Hidden service to scan. Type: class HiddenService.
#  @param n The maximum number of threads this function will create. Type: int.
#  @param fin_sem0 Semaphore we need to release at the end of the thread. Type: class threading.Semaphore.
#  @param state_changed_event Triggered if connect state of the hidden service changes.
#  @return 0
def scan_host(hid_serv,ndx_start,n,fin_sem0,state_changed_event):
    if hid_serv.connect_state == CONN_STATE_IS_BEING_CHECKED:
        try:
            check_host(hid_serv,state_changed_event)
	    #print "Host checked"
        except Exception as e:
            adr = hid_serv.onion_address
            thdprint(LOG_DEBUG,"Got exception while checking  for connectivity (the scan for this guy is finished) {0}. {1}".format(adr,str(e)))
            hid_serv.connect_state = CONN_STATE_FINISHED
            state_changed_event.set()
        fin_sem0.release()
	return 0
    # these semaphore and event will go to make_connect threads
    fin_sem1 = threading.Semaphore(n)
    fin_event1 = threading.Event()
    if ndx_start < len(hid_serv.ports_to_scan):
        thdprint(LOG_DEBUG,"Starting scan for {0}. Start port is {1}".format(hid_serv.onion_address,hid_serv.ports_to_scan[ndx_start]))
    #hid_serv.scan_is_finished = True
    interrupted = False
    #for port in hid_serv.ports_to_scan: 
    hid_serv_lock = threading.Lock()
    for port_ndx in range(ndx_start,len(hid_serv.ports_to_scan)): 
        fin_sem1.acquire()
	port = hid_serv.ports_to_scan[port_ndx]
	# next port to scan should be set in make_connect, so no worries here
	# If we are in one of the following states, we need to reconnect
	if (hid_serv.connect_state != CONN_STATE_CONNECTED):
            interrupted = True 
            break
        threading.Thread(target = make_connect,\
                args=(hid_serv,port_ndx,hid_serv_lock,fin_sem1,fin_event1),\
                name = "portscanner-{0}-{1}".format(hid_serv.onion_address,port)).start()
    # Wait until all subthreads are finished
    while (get_num_of_alive_threads("portscanner-{0}".format(hid_serv.onion_address)) != 0):
        #print "Wating for portscanner threads to die"
        #print get_num_of_alive_threads("portscanner-{0}".format(hid_serv.onion_address))
        fin_event1.wait(2)
        fin_event1.clear()
    # If subsequent threads were not able to restore connected state
    if interrupted and (hid_serv.connect_state != CONN_STATE_CONNECTED):
        thdprint(LOG_DEBUG,"{0} disconnected at port {1}. Will try to connect again".format(hid_serv.onion_address,hid_serv.ports_to_scan[hid_serv.next_port_ndx_to_scan]))
        hid_serv.connect_state = CONN_STATE_UNTRIED
        hid_serv.scan_is_started = False
    elif interrupted:
        thdprint(LOG_DEBUG,"{0} Interrupted but restored. Will resume soon at port {1}".format(hid_serv.onion_address,hid_serv.ports_to_scan[hid_serv.next_port_ndx_to_scan]))
        hid_serv.scan_is_started = False
    else:
        thdprint(LOG_DEBUG,"Finished scan for {0}".format(hid_serv.onion_address))
        hid_serv.connect_state = CONN_STATE_FINISHED
    state_changed_event.set()
    fin_sem0.release()
    return 0

## Initiate a port scanning for severl hidden services
#
#  @param hid_servs_to_scan_dict Hidden services we want to scan for open ports. Type: dict<HiddenService>.
#  @param ports_to_scan_list_generic Ports to scan, in case a hidden service does not have its own ports for scanning
#  @param n Maximum number of simultaneous threads per onion address.
#  @param m Maximum number of hidden services scanned in parallel.
#  @return 0
def make_scan(hid_servs_to_scan_dict,ports_to_scan_list_generic,n,m):    
    print "Starting..."
    host_scanner_sem = threading.Semaphore(m)
    hs_statechanged_event = threading.Event()
    while True: # Until we have num_of_finished == len(hid_servs_to_scan_dict):
        host_scanner_sem.acquire()
	current_hid_serv = None
	num_of_finished = 0
	for onion_address in hid_servs_to_scan_dict: 
	    hid_serv = hid_servs_to_scan_dict[onion_address]
	    # First let's look for a hid_serv for which we can start the scan
	    if (hid_serv.connect_state == CONN_STATE_CONNECTED) and (hid_serv.scan_is_started == False):
	        current_hid_serv = hid_serv
	        current_hid_serv.scan_is_started = True
		# we found a good candidate to work with
		break
            elif (hid_serv.connect_state == CONN_STATE_UNTRIED) and (current_hid_serv == None):
	        # We can work with this guy but let's search more. Maybe we find
		# somebody for whome we can start the scan
	        current_hid_serv = hid_serv
            elif hid_serv.connect_state == CONN_STATE_FINISHED:
	        num_of_finished += 1
	if num_of_finished == len(hid_servs_to_scan_dict):
	    break # break the while loop
	# Either all hosts are being checked for connection or being scanned
	# let's wait for event
        if current_hid_serv == None:
	    if(hs_statechanged_event.wait(2) == False):
                thdprint(LOG_DEBUG,"Waiting for events. Num of finished = {0}".format(num_of_finished))
	    hs_statechanged_event.clear()
	    if (get_num_of_alive_threads() <= 1):
                thdprint(LOG_DEBUG,"All threads are dead.")
            host_scanner_sem.release()
	    continue
        ps_ndx = current_hid_serv.next_port_ndx_to_scan # stands for port start
        #thdprint(LOG_DEBUG,"ps = {0}".format(ps_ndx))
	if current_hid_serv.connect_state == CONN_STATE_UNTRIED:
	    current_hid_serv.connect_state = CONN_STATE_IS_BEING_CHECKED

	if current_hid_serv.ports_to_scan == None:
	    current_hid_serv.ports_to_scan = ports_to_scan_list_generic
	
        threading.Thread(target = scan_host,\
                args=(current_hid_serv,ps_ndx,n,\
		host_scanner_sem,hs_statechanged_event),\
                name = "hostscanner-{0}".format(current_hid_serv.onion_address)).start()
	#current_hid_serv.scan_is_started = True
	if (get_num_of_alive_threads() <= 1):
            thdprint(LOG_DEBUG,"All threads are dead.")
    return 0
	
        

def main():
    config_params = ConfigParams()
    config_params.init_from_command_line(sys.argv)
    #1. First, abort the scan if the Tor socks is unavailable
    #2. Second, for each hidden service, before starting the scanning,
    #   check if its descriptor is available. It does not make sense to
    #   launch all those scanning threads if you know that they all
    #   will return with 'desc unavailable' error message.
    #thdprint(LOG_DEBUG,"Going to scan ports {0}".format(config_params.ports_to_scan))
    # <config_params.ports_to_scan> is used if hid_serv_to_scan_dict element does not
    #   has a personal list  of ports.
    make_scan(config_params.hid_servs_to_scan_dict,\
              config_params.ports_to_scan,\
	      config_params.max_num_of_threads,\
	      config_params.max_num_of_hs_scanned_in_parallel)
    return 0

##########################################
############ MAIN ########################
##########################################

main()
