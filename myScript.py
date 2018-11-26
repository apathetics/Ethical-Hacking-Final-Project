import nmap
import sys
import vulners
import re

def nmapScan(ipRange = '127.0.0.1', portRange = 'default'):
	'''
	Perform initial Nmap scan on specified ip and port range
	Defaults to localhost and the default 1000 common ports scanned by nmap
	'''
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

		print("Found live host " + host)
		for port in scan_results[host]:
			port_info = scan_results[host][port]
			service_string = port_info['name'] + ", " + port_info['product'] + " " + port_info['version']

			print("\tport " + str(port) + " open: " + service_string)

	return scan_results


def vulnerability_scan(nmap_results):
	'''
	Searches for known CVE entries from the vulners CVE database
	using discovered ports and services from the previous nmap scan
	'''

	# TODO: hide api key?
	vulners_api = vulners.Vulners(api_key="OW8179OUUBEZGQZ0V6NBZHOXSMX2DRNNB811MH7YV6D65N7YSGXKZQQKCZA6JX9W")
	vulnerability_results = {}

	for host in nmap_results:
		print('Scanning for Common Vulnerabilities and Exposures for host {}'.format(host))

		port_list = nmap_results[host]
		for port in port_list:
			port_info = port_list[port]

			if port_info['product'] == '' and port_info['version'] = '':
				service_string = ''
			else:
				service_string = ", " + port_info['product'] + " " + port_info['version']
			print('\tPort ' + str(port) + ": " + port_info['name'] + service_string)

			search_result = vulners_api.search(port_info['product'] + " " + port_info['version'])

			vulnerability_results[port] = extract_CVEs(search_result)

	return vulnerability_results


def extract_CVEs(search_results):
	'''
	Uses regex to parse the vulners_api search result description for relevant CVE IDs
	'''
	CVE_list = []
	for result in search_results:
		description = result['description']
		CVE_list += re.findall('CVE\S*', description)

	return CVE_list


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

