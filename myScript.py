import nmap
import sys


def nmapScan(ipRange = '127.0.0.1', portRange = '1-1000'):

	print("Doing port scan of range {} on ports {}. ".format(ipRange, portRange))
	nm = nmap.PortScanner()
	nm.scan(ipRange, portRange)

	# prints out info in this format:
	# host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe
	# we can parse this for something? or use vulnscan
	print(nm.csv())


if __name__ =='__main__':

	# step one: doing the nmap scan and parsing the results into dictionary
	# read in arguments, assume provided as (ip, port) in that order
	# we can specify arguments like -ip= and -port= respectively later
	if len(sys.argv) == 1:
		nmapResults = nmapScan()
	else:
		ipRange = sys.argv[1]
		portRange = sys.argv[2]
		nmapResults = nmapScan(ipRange, portRange)

