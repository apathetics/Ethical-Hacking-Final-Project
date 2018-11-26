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
	vulners_api = vulners.Vulners(api_key="B0L6QKO58TZBGG18S3M633CL7NVE192WPS7NCSS6IZ7N4HSDPLF8ZZI3IC8OI3XV")
	vulnerability_results = {}

	for host in nmap_results:
		print('Scanning for Common Vulnerabilities and Exposures for host {}'.format(host))

		vulnerability_results[host] = {}
		port_list = nmap_results[host]
		for port in port_list:
			port_info = port_list[port]

			if port_info['product'] == '' and port_info['version'] == '':
				service_string = ''
			else:
				service_string = ", " + port_info['product'] + " " + port_info['version']
			print('Port ' + str(port) + ": " + port_info['name'] + service_string)

			search_result = vulners_api.search(port_info['product'] + " " + port_info['version'])

			cve_list = extract_CVEs(search_result)
			vulnerability_results[host][port] = cve_list

			if(len(cve_list) > 0):
				print("Possible CVEs Detected:")
			for cve in vulnerability_results[host][port]:
				print("\t" + unicode(cve))

	return vulnerability_results


def extract_CVEs(search_results):
	'''
	Uses regex to parse the vulners_api search result description for relevant CVE IDs
	'''
	cve_list = []
	for result in search_results:
		description = result['description']
		cve_list += re.findall('CVE\S*', description)

	return cve_list


def run_scripts(vulnerability_results):
	'''
	Searches for relevant NSE vulns scripts corresponding to the possible CVE IDs
	and runs them if any are found
	'''
	scripts = {}

	for host in vulnerability_results:
		port_info = vulnerability_results[host]
		for port in port_info:
			cve_list = port_info[port]
			for cve in cve_list:
				if cve in vuln_scripts:
					scripts[cve] = vuln_scripts[cve]

	print("Found %d relevant NSE vuln scripts".format(len(scripts)))
	for script in scripts:
		print("Running {} to detect vulnerability of host {} to {}".format(script, host, cve))


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
	# nmap NSE vulnerability scripts and run for more information
	run_scripts(vulnerability_results)

