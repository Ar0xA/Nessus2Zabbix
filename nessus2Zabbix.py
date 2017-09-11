
#This takes as input a .nessus scan file with either vulnerability or compliance info (or both)
#and passes it to zabbix.
#
#Zabbix keys:
#
#cis.compliance.failed
#cis.compliance.passed
#cis.compliance.warning
#nessus.policy.name
#nessus.scan.name
#nessus.date.latest.scan
#vulnerability.critical
#vulnerability.high
#vulnerability.low
#vulnerability.medium

#autor: @Ar0xA / ar0xa@tldr.nu

from bs4 import BeautifulSoup

import argparse
import sys
import os
import io
import json
import ConfigParser
from pyZabbixSender import pyZabbixSender #local import from https://github.com/kmomberg/pyZabbixSender/blob/master/pyZabbixSender.py

from nessrest import ness6rest
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#here we download a report directly from the nessus API
def download_nessus_report(args, keys):
    nessus_url = "https://" + args.nessusserver + ":" + str(args.nessusport)
    scanner = None
    scanner = ness6rest.Scanner(url=nessus_url, api_akey=keys['accessKey'], api_skey=keys['secretKey'], insecure=args.nessusinsecure)
    if scanner:
        print "API login succeeded"
        scanner.action(action='scans', method='get')
        if not len( scanner.res['scans']) > 0:
            print "Did not find any available scans!"
            sys.exit(1)
        scans = scanner.res['scans']
        folders = scanner.res['folders']
        #we dont want scans from trash folder
        for f in folders:
            if f['type'] == 'trash':
                trash_id=f['id']

        #iterate through scans, drop crap from the trash folder
        found_scan = False
        for s in scans:
            if s['folder_id'] != trash_id:
                scanner.scan_name = s['name']
                scanner.scan_id = s['id']

                #only export if the scan is completed and if it's the correct scan
                if (s['status'] == 'completed') and (scanner.scan_name == args.nessusscanname):
                    found_scan = True
                    with io.open(args.nessustmp + '/' + args.nessusscanname, 'wb') as fp:
                        print "Found valid scan, Writing output file to tmp directory"
                        fp.write(scanner.download_scan(export_format='nessus'))
                        fp.close()

        if not found_scan:
            print "Did not find any scan to export. Maybe it wasn\'t done yet or be sure to check the scanname or API file and try again."
            sys.exit(1)


#here we parse results from the nessus file, we extract the vulnerabiltiy results and return that in an array
#in the format [ ['hostname', int(low), int(Medium), int(High), int(Critical)], [etc.] ]
def parse_vuln_results(hosts):
    print "Checking for vulnerability results..."
    tmp_res=[]
    is_data = False
    for host in hosts:
        low = 0
        medium = 0
        high = 0
        critical = 0
        host_name = host['name']
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            #ok, so we need to find  all report items that do NOT include <compliance>true</compliance>
            try:
                vuln_item = rItem.find('compliance')
                risk_factor = rItem.find('risk_factor')
                if (vuln_item) == None and ( risk_factor.get_text() == 'Low'):
                    low += 1
                    is_data = True
                elif (vuln_item) == None and ( risk_factor.get_text() == 'Medium'):
                    medium += 1
                    is_data = True
                elif (vuln_item) == None and ( risk_factor.get_text() == 'High'):
                    high += 1
                    is_data = True
                elif (vuln_item) == None and ( risk_factor.get_text() == 'Critical'):
                    critical += 1
                    is_data = True
            except:
                print rItem
                sys.exit(1)
        print '%s has %i vulnerabilies low, %i medium, %i high, %i critical' % (host_name, low, medium, high, critical)
        tmp_res.append([host_name, low, medium, high, critical])
    #ok look, if everything is 0...lets just give up
    if is_data:
        return tmp_res
    else:
        return []

#here we parse results from the nessus file, we extract the compliance results and return that in an array
#in the format [ ['hostname', int(passed), int(warning), int(failed)], [etc.] ]
def parse_comp_results(hosts):
    print "Checking for compliance results..."
    tmp_res=[]
    is_data = False
    # lets go through each host
    for host in hosts:
        failed = 0
        passed = 0
        warning = 0
        host_name = host['name']
        #lets iterate through the reportItem, here the compliance items will be
        reportItems = host.findAll('reportitem')
        for rItem in reportItems:
            #ok lets find all compliance result items, and ONLY compliance items
            try:
                compliance_item = rItem.find('cm:compliance-result')
                if (compliance_item != None) and(compliance_item.get_text() == 'PASSED'):
                    passed += 1
                    is_data = True
                elif(compliance_item != None) and(compliance_item.get_text() == 'FAILED'):
                    failed += 1
                    is_data = True
                elif(compliance_item != None) and(compliance_item.get_text() == 'WARNING'):
                    warning += 1
                    is_data = True
            except:
                print rItem
                sys.exit(1)
        print '%s has %i compliance passed, %i warnings and %i failed' % (host_name, passed, warning, failed)
        tmp_res.append([host_name, passed, warning, failed])

    #look ok, if everything is 0 lets just give up
    if is_data:
        return tmp_res
    else:
        return []

#Send compliance data to Zabbix
def send_comp_to_zabbix(compliance_results, args_server, args_port, nessus_metadata, args_fake):
    z = pyZabbixSender(server=args_server, port=args_port)

    for comp_result in compliance_results:
        #first we add the metadata
        z.addData(comp_result[0],'nessus.scan.name',nessus_metadata[0]) #scanname
        z.addData(comp_result[0],'nessus.policy.name',nessus_metadata[1]) #policyname
        z.addData(comp_result[0],'nessus.date.latest.scan',nessus_metadata[2]) #scan time
        #now we add the values
        z.addData(comp_result[0], 'cis.compliance.passed', comp_result[1])
        z.addData(comp_result[0], 'cis.compliance.warning', comp_result[2])
        z.addData(comp_result[0], 'cis.compliance.failed', comp_result[3])

        #debug
        #z.printData()
        if args_fake:
            print "Faking. This is where I send data"
        else:
            results = z.sendDataOneByOne()
            for (code,data) in results:
                if code != z.RC_OK:
                    print "Failed to send %s" % str(data)
        z.clearData()
    print "Done sending compliance data"

def send_vuln_to_zabbix(vulnerability_results, args_server, args_port, nessus_metadata, args_fake):
    z = pyZabbixSender(server=args_server, port=args_port)

    for vuln_result in vulnerability_results:
        #first we add the metadata
        z.addData(vuln_result[0],'nessus.scan.name',nessus_metadata[0]) #scanname
        z.addData(vuln_result[0],'nessus.policy.name',nessus_metadata[1]) #policyname
        z.addData(vuln_result[0],'nessus.date.latest.scan',nessus_metadata[2]) #scan time
        #now we add the values
        z.addData(vuln_result[0], 'vulnerability.low', vuln_result[1])
        z.addData(vuln_result[0], 'vulnerability.medium', vuln_result[2])
        z.addData(vuln_result[0], 'vulnerability.high', vuln_result[3])
        z.addData(vuln_result[0], 'vulnerability.critical', vuln_result[4])

        #debug
        #z.printData()
        if args_fake:
            print "Faking. This is where I send data"
        else:
            results = z.sendDataOneByOne()
            for (code,data) in results:
                if code != z.RC_OK:
                    print "Failed to send %s" % str(data)
        z.clearData()
    print "Done sending vulnerability data"

def parse_args():
    parser = argparse.ArgumentParser(description = 'Push data into zabbix from a .nessus result file.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input', help = 'Input file in .nessus format',
        default = None)
    parser.add_argument('-zs', '--zabbixserver', help = 'Zabbix server',
        default = '127.0.0.1')
    parser.add_argument('-zp', '--zabbixport', help = 'Zabbix port',
        default = 10051)
    parser.add_argument('-t', '--type', help = 'What type of result to parse the file for.', choices = ['both', 'vulnerability','compliance' ],
        default = 'both')
    parser.add_argument('-f','--fake', help = 'Do everything but actually send data to Zabbix', action = 'store_true')
    parser.add_argument('-ns','--nessusserver', help ='Nessus server',
        default = '127.0.0.1')
    group.add_argument('-nr','--nessusscanname', help = 'The scan report to download',
        default = None)
    parser.add_argument('-np', '--nessusport', help ='Nessus server port',
        default = 8834)
    parser.add_argument('-nc', '--nessuscapath', help ='Nessus CA server path',
        default = None)
    parser.add_argument('-ni', '--nessusinsecure', help ='Allow insecure certificates for Nessus API connection',
        default = 'False')
    parser.add_argument('-nk', '--nessuskeyfile', help ='Nessus API key file for authentication',
        default = './nessus_api.key.json')
    parser.add_argument('-nt', '--nessustmp', help ='Nessus tmp path to save exported file',
        default = '/tmp')
    parser.add_argument('-nd', '--nessusdeletetmp', help = 'Delete the downloaded file in the tmp directory after parsing',
        action = 'store_false')
    group.add_argument('-c', '--config', help = 'Config file for script to read settings from. Overwrites all other cli parameters', default = None)
    args = parser.parse_args()
    return args

#replace args from config file instead
def replace_args(args):
    if os.path.isfile(args.config):
        print "Reading configuration from config file"
        Config = ConfigParser.ConfigParser()
        try:
            Config.read(args.config)
            args.input = Config.get("General","Input")
            args.type = Config.get("General","Type")
            args.fake = bool(Config.get("General","Fake"))
            args.zabbixserver = Config.get("Zabbix","ZabbixServer")
            args.zabbixport = int(Config.get("Zabbix","ZabbixPort"))
            args.nessusserver = Config.get("Nessus", "NessusServer")
            args.nessusport = int(Config.get("Nessus", "NessusPort"))
            args.nessuscapath = Config.get("Nessus", "NessusCAPath")
            args.nessusscanname = Config.get("Nessus", "NessusScanName")
            args.nessusinsecure = bool(Config.get("Nessus", "NessusInsecure"))
            args.nessuskeyfile = Config.get("Nessus", "NessusKeyFile")
            args.nessustmp = Config.get("Nessus", "NessusTMP")
            args.nessusdeletetmp = bool(Config.get("Nessus", "NessusDeleteTMP"))
        except IOError:
                print('could not read config file "' + args.config + '".')
                sys.exit(1)
    else:
        print('"' + args.config + '" is not a valid file.')
        sys.exit(1)
    return args

def main():
    args = parse_args()

    #do we have a config file instead of cli?
    if args.config:
        args = replace_args(args)

    #ok, if not
    if (not args.input) and (not args.nessusscanname):
        print('Need input file or Nessus scan to export. Specify one in the configuation file,  with -i (file) or -rn (reportname)\n See -h for more info')
        sys.exit(1)

    #ok so we assume we have to download a report
    if args.nessusscanname:
        print "Parsing scan results from Nessus API"
        keys=None
        if not args.input:
            #do we have api
            if os.path.isfile(args.nessuskeyfile):
                try:
                    f_key = open(args.nessuskeyfile, 'r')
                    try:
                        keys = json.loads(f_key.read())
                    except ValueError as err:
                        print(str(err))
                        print('could parse read key file "' + nessuskeyfile + '".')
                    f_key.close()
                except IOError:
                    print('could not read key file "' + args.nessuskeyfile + '".')
                    sys.exit(1)
            else:
                print('"' + args.nessuskeyfile + '" is not a valid file.')
                sys.exit(1)

        #what about CA path?
        if args.nessuscapath and not os.path.isdir(args.nessuscapath):
            print('CA path "' + args.nessuscapath + '" not found.')
            sys.exit(1)
        #ok, lets assume the rest is fine then
        download_nessus_report(args, keys)

    if args.input:
        nessus_scan_file = args.input
    else:
        nessus_scan_file = args.nessustmp + "/" + args.nessusscanname
    print "Nessus file to parse is %s" % (nessus_scan_file)

    # read the file..might be big though...
    with open(nessus_scan_file, 'r') as f:
        print 'Parsing file %s as xml into memory, hold on...' % (args.input)
        nessus_xml_data = BeautifulSoup(f.read(), 'lxml')

    #find metadata we need
    #todo: if not find items..is this valid nessus file?
    tmp_scanname = nessus_xml_data.report['name']
    if len(tmp_scanname) == 0:
        print 'Didn\'t find report name in file. is this a valid nessus file?'
        sys.exit(1)

    tmp_policyname = nessus_xml_data.find('policyname').get_text()
    tmp_scantime = ""
    #scan is the first HOST_START that we find
    tmp_tags = nessus_xml_data.reporthost.findAll('tag') #tag['name'']
    for tag in tmp_tags:
        if tag['name'] ==  'HOST_START':
            tmp_scantime = tag.get_text()

    nessus_metadata= [tmp_scanname, tmp_policyname, tmp_scantime]

    # see if there are any hosts that are reported on
    hosts = nessus_xml_data.findAll('reporthost')
    if len(hosts) == 0:
        print 'Didn\'t find any hosts in file. Is this a valid nessus file?'
        sys.exit(1)
    else:
        print 'Found %i hosts' % (len(hosts))

    if args.type == "both" or args.type == "compliance":
        #ok now that we have the compliance results, lets make some magic!
        compliance_result = []
        compliance_result = parse_comp_results(hosts)
        if len(compliance_result) > 0:
            print "Sending compliance info to Zabbix server: %s" % (args.zabbixserver)
            send_comp_to_zabbix(compliance_result, args.zabbixserver, args.zabbixport, nessus_metadata, args.fake)
        else:
            print "Did not find any compliance items, not sending any information\n"

    if args.type == "both" or args.type == "vulnerability":
        vulnerability_result = []
        vulnerability_result = parse_vuln_results(hosts)
        if len(vulnerability_result) >0:
            print "Sending vulnerability info to Zabbix server: %s" % (args.zabbixserver)
            send_vuln_to_zabbix(vulnerability_result, args.zabbixserver, args.zabbixport, nessus_metadata, args.fake)
        else:
            print "Did not find any vulnerability items, not sending any information\n"


    if args.nessusdeletetmp:
        try:
            os.remove(args.nessustmp + "/" + args.nessusscanname)
        except IOError:
            print "Deleting %s failed from %s." % (args.nessusscanname, args.nessustmp)
            sys.exit(1)
        print "Deleted tmp file successfully."
    else:
        print "Not deleting scan file. you can find it in %s\\%s" % (args.nessustmp, args.nessusscanname)

if __name__ == "__main__":
  main()
  print "Done."
