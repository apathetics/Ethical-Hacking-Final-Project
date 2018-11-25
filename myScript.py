import nmap
import sys
from subprocess import check_output


def nmapScan(ipRange = '127.0.0.1', portRange = '1-1000'):

	print("Doing port scan of range {} on ports {}. ".format(ipRange, portRange))
	nm = nmap.PortScanner()
	nm.scan(ipRange, portRange)

	# prints out info in this format:
	# host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe
	# we can parse this for something? or use vulnscan
	print(nm.csv())

	# need to have a vulnerable system to test on? and then to figure out how to parse the result...
	result = check_output("nmap --script nmap-vulners -sV " + ipRange, shell=True)
	print(result)


if __name__ =='__main__':

	# step one: doing the nmap scan and parsing the results into dictionary
	# read in arguments, assume provided as (ip, port) in that order
	# we can specify arguments like -ip= and -port= respectively later
	numArgs = len(sys.argv)

	if numArgs == 1:
		nmapResults = nmapScan()
	else:
		ipRange = sys.argv[1]
		portRange = sys.argv[2] if numArgs > 2 else "1-1000"

		nmapResults = nmapScan(ipRange, portRange)

