# Nessus2Zabbix
Parse Nessus compliance and vulnerability information from the server or a .nessus file and pass it to Zabbix.<br>
<br>
Can read both from cli (nessus2zabbix -h) or from config file (see example).<br>
<br>
Can read from local .nessus file (-i ./path/to/file) or talk to the API of the server.<br>
<br>
# Example 1: 
#use config file<br>
python nessus2zabbix.py -c nessus2zabbix.config<br>
<u>note</u>: using a config file overwrites ALL other cli arguments<br>
<br>
# Example 2: 
#use cli with local nessus file and remote Zabbix server, compliance information only<br>
python nessus2zabbix.py -i ./my_scan.nessus -t compliance -zs 192.168.1.30<br>

# Example 3: 
#use cli with remote Nessus server (untrusted SSL certificate) and remote Zabbix server<br>
python nessus2zabbix.py -ns 192.168.1.230 -nr "my_scan" -ni True -nk ./nessus_api.key.json.example -zs 192.168.1.30

# Parameters:
  -h, --help            show this help message and exit <br>
  <br>
  -i INPUT, --input INPUT<br>
                        Input file in .nessus format<br>
                        <br>
  -zs ZABBIXSERVER, --zabbixserver ZABBIXSERVER <br>
                        Zabbix server (Default: 127.0.0.1)<br>
                        <br>
  -zp ZABBIXPORT, --zabbixport ZABBIXPORT<br>
                        Zabbix port (Default: 10051)<br>
                        <br>
  -t {both,vulnerability,compliance}, --type {both,vulnerability,compliance}<br>
                        What type of result to parse the file for.  (Default: Both)<br>
                        <br>
  -f, --fake            Do everything but actually send data to Zabbix (Default: False)<br>
  <br>
  -ns NESSUSSERVER, --nessusserver NESSUSSERVER<br>
                        Nessus server (Default: 127.0.0.1)<br>
                        <br>
  -nr NESSUSSCANNAME, --nessusscanname NESSUSSCANNAME<br>
                        The scan report to download <br>
                        <br>
  -np NESSUSPORT, --nessusport NESSUSPORT<br>
                        Nessus server port (Default: 8834)<br>
                        <br>
  -nc NESSUSCAPATH, --nessuscapath NESSUSCAPATH<br>
                        Nessus CA server path (Default: None)<br>
                        <br>
  -ni NESSUSINSECURE, --nessusinsecure NESSUSINSECURE<br>
                        Allow insecure certificates for Nessus API connection (Default: False)<br>
                        <br>
  -nk NESSUSKEYFILE, --nessuskeyfile NESSUSKEYFILE<br>
                        Nessus API key file for authentication (Default: ./nessus_api.key.json)<br>
                        <br>
  -nt NESSUSTMP, --nessustmp NESSUSTMP<br>
                        Nessus tmp path to save exported file (Default: /tmp)<br>
                        <br>
  -nd, --nessusdeletetmp<br>
                        Delete the downloaded file in the tmp directory after<br>
                        parsing (Default: True)<br>
                        <br>
  -c CONFIG, --config CONFIG<br>
                        Config file for script to read settings from.<br>
                        Overwrites all other cli parameters!<br>

# Zabbix keys
cis.compliance.failed<br>
cis.compliance.passed<br>
cis.compliance.warning<br>
nessus.policy.name<br>
nessus.scan.name<br>
nessus.date.latest.scan<br>
vulnerability.critical<br>
vulnerability.high<br>
vulnerability.low<br>
vulnerability.medium<br>
