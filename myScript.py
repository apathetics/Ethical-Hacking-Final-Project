import nmap
import sys
import vulners
import re
import subprocess

vuln_scripts = {
    'CVE-2010-0533': 'afp-path-vuln',
    'CVE-2011-1002': 'broadcast-avahi-dos',
    'CVE-2004-2687': 'distcc-cve2004-2687',
    'CVE-2010-1938': 'ftp-libopie',
    'CVE-2011-2523': 'ftp-vsftpd-backdoor',
    'CVE-2010-4221': 'ftp-vuln-cve2010-4221',
    'CVE-2008-3922': 'http-awstatstotals-exec',
    'CVE-2010-2333': 'http-litespeed-sourcecode-download',
    'CVE-2011-0049': 'http-majordomo2-dir-traversal',
    'CVE-2014-6271': 'http-shellshock',
    'CVE-2014-7169': 'http-shellshock',
    'CVE-2009-3733': 'http-vmware-path-vuln',
    'CVE-2006-3392': 'http-vuln-cve2006-3392',
    'CVE-2009-3960': 'http-vuln-cve2009-3960',
    'CVE-2010-0738': 'http-vuln-cve2010-0738',
    'CVE-2010-2861': 'http-vuln-cve2010-2861',
    'CVE-2011-3192': 'http-vuln-cve2011-3192',
    'CVE-2011-3368': 'http-vuln-cve2011-3368',
    'CVE-2012-1823': 'http-vuln-cve2012-1823',
    'CVE-2013-0156': 'http-vuln-cve2013-0156',
    'CVE-2013-6786': 'http-vuln-cve2013-6786',
    'CVE-2013-7091': 'http-vuln-cve2013-7091',
    'CVE-2014-2126': 'http-vuln-cve2014-2126',
    'CVE-2014-2127': 'http-vuln-cve2014-2127',
    'CVE-2014-2128': 'http-vuln-cve2014-2128',
    'CVE-2014-2129': 'http-vuln-cve2014-2129',
    'CVE-2014-3704': 'http-vuln-cve2014-3704',
    'CVE-2014-8877': 'http-vuln-cve2014-8877',
    'CVE-2015-1427': 'http-vuln-cve2015-1427',
    'CVE-2015-1635': 'http-vuln-cve2016-1635',
    'CVE-2017-1001000': 'http-vuln-cve2017-1001000',
    'CVE-2017-5638': 'http-vuln-cve2017-5638',
    'CVE-2017-5639': 'http-vuln-cve2017-5639',
    'CVE-2017-8917': 'http-vuln-cve2017-8917',
    'CVE-2006-2369': 'realvnc-auth-bypass',
    'CVE-2012-1182': 'samba-vuln-cve-2012-1182',
    'CVE-2017-7494': 'smb-vuln-cve-2017-7494',
    'CVE-2009-3103': 'smb-vuln-cve2009-3103',
    'CVE-2010-4344': 'smtp-vuln-cve2010-4344',
    'CVE-2010-4345': 'smtp-vuln-cve2010-4344',
    'CVE-2011-1720': 'smtp-vuln-cve2011-1720',
    'CVE-2011-1764': 'smtp-vuln-cve2011-1764',
    'CVE-2014-0224': 'ssl-ccs-injection',
    'CVE-2014-0160': 'ssl-heartbleed',
    'CVE-2015-3197': 'sslv2-drown',
    'CVE-2016-0703': 'sslv2-drown',
    'CVE-2016-0800': 'sslv2-drown',
    'CVE-2016-9244': 'tls-ticketbleed'
}


def nmapScan(ipRange='127.0.0.1', portRange='default'):
    '''
	Perform initial Nmap scan on specified ip and port range
	Defaults to localhost and the default 1000 common ports scanned by nmap
	'''
    print("Doing port scan of range {} on ports {}. \n".format(ipRange, portRange))
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

            print("\tPort " + str(port) + " open: " + service_string)

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
        print('\nScanning for Common Vulnerabilities and Exposures for host {}'.format(host))

        vulnerability_results[host] = {}
        port_list = nmap_results[host]
        for port in port_list:
            port_info = port_list[port]

            if port_info['product'] == '' and port_info['version'] == '':
                service_string = ''
            else:
                service_string = ", " + port_info['product'] + " " + port_info['version']
            print('\tPort ' + str(port) + ": " + port_info['name'] + service_string)

            search_result = vulners_api.search(port_info['product'] + " " + port_info['version'])

            cve_list = extract_CVEs(search_result)
            vulnerability_results[host][port] = cve_list

            if (len(cve_list) > 0):
                print("\nPossible CVEs Detected:")
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
        cve_list += re.findall('CVE-\d{4}-\d{4}', description)

    return list(set(cve_list))


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

    print("\nFound {} relevant NSE vuln scripts".format(len(scripts)))
    for cve in scripts:
        print("Running \'{}\' to detect vulnerability of host \'{}\' to \'{}\' \n".format(scripts[cve], host, cve))
        argument = '--script=' + scripts[cve]
        
        scriptOutput = subprocess.check_output(['nmap', host, argument])
        if scripts[cve] in scriptOutput:
            print("Script results:")
            print(scriptOutput)
        else: 
            print("Script \'{}\' did not find a vulnerability.".format(scripts[cve]))


if __name__ == '__main__':

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
