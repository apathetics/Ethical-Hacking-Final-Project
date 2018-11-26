import nmap
import sys
import vulners

def nmapScan(ipRange = '127.0.0.1', portRange = 'default'):

	print("Doing port scan of range {} on ports {}. ".format(ipRange, portRange))
	nm = nmap.PortScanner()
	nm.scan(ipRange)
	scan_results = parseNmapResults(nm)

	print(scan_results)


def parseNmapCSV(nm):
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

