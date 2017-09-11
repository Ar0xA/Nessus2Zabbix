# Nessus2Zabbix
Parse Nessus compliance and vulnerability information from the server or a .nessus file and pass it to Zabbix.

Can read both from cli (nessus2zabbix -h) or from config file (see example).

Can read from local .nessus file (-i ./path/to/file) or talk to the API of the server

# Example: use config file
python nessus2zabbix.py -c nessus2zabbix.config

# Example: use cli with local nessus file and remote Zabbix server, compliance information only
python nessus2zabbix.py -i ./my_scan.nessus -t compliance -zs 192.168.1.30

# Example: use cli with remote Nessus server (untrusted SSL certificate) and remote Zabbix server
python nessus2zabbix.py -ns 192.168.1.230 -nr "my_scan" -ni True -nk ./nessus_api.key.json.example -zs 192.168.1.30

# Parameters:
  -h, --help            show this help message and exit
  
  -i INPUT, --input INPUT
                        Input file in .nessus format
                        
  -zs ZABBIXSERVER, --zabbixserver ZABBIXSERVER 
                        Zabbix server 
                        
  -zp ZABBIXPORT, --zabbixport ZABBIXPORT
                        Zabbix port
                        
  -t {both,vulnerability,compliance}, --type {both,vulnerability,compliance}
                        What type of result to parse the file for.
                        
  -f, --fake            Do everything but actually send data to Zabbix
  
  -ns NESSUSSERVER, --nessusserver NESSUSSERVER
                        Nessus server
                        
  -nr NESSUSSCANNAME, --nessusscanname NESSUSSCANNAME
                        The scan report to download
                        
  -np NESSUSPORT, --nessusport NESSUSPORT
                        Nessus server port
                        
  -nc NESSUSCAPATH, --nessuscapath NESSUSCAPATH
                        Nessus CA server path
                        
  -ni NESSUSINSECURE, --nessusinsecure NESSUSINSECURE
                        Allow insecure certificates for Nessus API connection
                        
  -nk NESSUSKEYFILE, --nessuskeyfile NESSUSKEYFILE
                        Nessus API key file for authentication
                        
  -nt NESSUSTMP, --nessustmp NESSUSTMP
                        Nessus tmp path to save exported file
                        
  -nd, --nessusdeletetmp
                        Delete the downloaded file in the tmp directory after
                        parsing
                        
  -c CONFIG, --config CONFIG
                        Config file for script to read settings from.
                        Overwrites all other cli parameters

