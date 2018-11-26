import nmap
import sys
import vulners

def nmapScan(ipRange = '127.0.0.1', portRange = 'default'):

	print("Doing port scan of range {} on ports {}. ".format(ipRange, portRange))
	nm = nmap.PortScanner()

	if portRange == 'default':
		nm.scan(ipRange)
	else:
		nm.scan(ipRange, portRange)

	scan_results = parse_nmap_results(nm)

	return scan_results


def parse_nmap_results(nm):
	'''
	Returns dictionary of hosts and their discovered ports

	Ex:
		{'192.168.1.68' : {
				22 : {
					'product': 'OpenSSH',
					'state': 'open',
					'version': '4.7p1 Debian 8ubuntu1',
					'name': 'ssh',
					'conf': '10',
					'extrainfo': 'protocol 2.0',
					'reason': 'syn-ack',
					'cpe': 'cpe:/o:linux:linux_kernel'
				}
			}
		}
	'''
	hosts = nm.all_hosts()
	scan_results = {}

	for host in hosts:
		scan_results[host] = nm[host]['tcp']

	return scan_results


def vulnerability_scan(nmap_results):
	'''
	Searches for known CVE entries from the vulners CVE database
	using discovered ports and services from the previous nmap scan
	'''

	vulners_api = vulners.Vulners(api_key="OW8179OUUBEZGQZ0V6NBZHOXSMX2DRNNB811MH7YV6D65N7YSGXKZQQKCZA6JX9W")
	vulnerability_results = {}

	for host in nmap_results:
		port_list = nmap_results[host]

		for port in port_list:
			port_info = port_list[port]

			search_result = vulners_api.search(port_info['product'] + " " + port_info['version'])

			print(search_result)


if __name__ =='__main__':

	# step one: doing the nmap scan and parsing the results into dictionary
	# read in arguments, assume provided as (ip, port) in that order
	# we can specify arguments like -ip= and -port= respectively later
	numArgs = len(sys.argv)

	if numArgs == 1:
		nmapResults = nmapScan()
	else:
		ipRange = sys.argv[1]
		portRange = sys.argv[2] if numArgs > 2 else "default"

		nmapResults = nmapScan(ipRange, portRange)

	# step two: using the information from the nmap scan, search for relevant
	# CVE IDs from the vulners CVE database and parse the results
	vulnerability_results = vulnerability_scan(nmapResults)

	# step three: using the potential CVE IDs, search for supplemental
	# nmap NSE vulnerability scripts to run for more information

