# -*- coding: utf-8 -*-
"""
Created on Feb 28, 2021
@author: vince nkawu
@email: nkawuv@gmail.com
"""

import copy 
import configparser
import logging
import time
import json
import requests
import csv
from datetime import date, timedelta
import re
import os
import io
import sys
#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#read application properties from properties file
FORMAT = '%(asctime)-15s: %(levelname)s:  %(message)s'
logging.basicConfig(filename='/home/vince/log/logSplunkESAPICall_ES_Consolidate.log', format=FORMAT, level=logging.DEBUG)
retries=5
config = configparser.ConfigParser()
config.read('/home/vince/inputs_and_outputs/app.properties')

url = config.get('splunkProperties','splunk.url')
port = config.get('splunkProperties','splunk.port')
username = config.get('splunkProperties','splunk.username')
password = config.get('splunkProperties','splunk.password')
search = config.get('splunkProperties','splunk.search')
timeout = config.get('splunkProperties','splunk.timeout')
timeout  = int(timeout)
matched_critical_hostname_set =  set()
matched_critical_ip_set =  set()

## Paramters might need to update
TANIUM_FILE = "/home/vince/inputs_and_outputs/tanium.csv"
TANIUM_COLUMN_NAMES = ['IPv4_Address', 
                        'Computer_Name', 
                        'Domain_Name', 
                        'mac_address',
                        'operating_system',
                        'os_country_code_name']

COMPUTER_FILE = "/home/vince/inputs_and_outputs/cmdb_ci_computer.csv"
COMPUTER_COLUMN_NAMES = [ 'ip_address',
                            'fqdn',
                            'name',
                            'dns_domain',
                            'location',
                            'u_managing_opco',
                            'os',
                            'sys_class_name',
                            'managed_by']

APP_FILE = "/home/vince/inputs_and_outputs/cmdb_ci_business_app.csv"
APP_COLUMN_NAMES=['name', 
                    'u_eai_id',	
                    'apm_business_process',	
                    'u_it_lead',	
                    'u_owning_mgr',	
                    'support_group',
                    'it_application_owner',	
                    'platform']


OPCO_FILE = "/home/vince/inputs_and_outputs/normalize_opco.csv"
OPCO_COLUMN_NAMES = ['normalize',
                        'opco']

MAPPING_FILE="/home/vince/inputs_and_outputs/cmdb_rel_ci.csv"
MAPPING_COLUMN_NAMES = ['parent.ref_cmdb_ci_business_app.u_eai_id',	'child']

STATIC_ASSETS_FILE = "/home/vince/inputs_and_outputs/static_assets.csv"
STATIC_ASSETS_COLUMN_NAMES = ['devicetype',
                                'multi_user',
                                'category',
                                'os_domain',
                                'os',
                                'hostname',
                                'dns_domain',
                                'dns',
                                'ip',
                                'opco']

SCANNER_FILE = "/home/vince/inputs_and_outputs/assets_known_scanners_updated.csv"
SCANNER_COLUMN_NAMES = ['ip', 
                        'mac', 
                        'nt_host', 
                        'dns', 
                        'owner', 
                        'priority', 
                        'lat', 
                        'long', 
                        'city',
                        'state', 
                        'country', 
                        'bunit', 
                        'category', 
                        'pci_domain', 
                        'is_expected',
                        'should_timesync', 
                        'should_update', 
                        'requires_av', 
                        'cim_entity_zone',
                        'function',
                        'os']

CRITICAL_ASSETS_FILE = "/home/vince/inputs_and_outputs/critical_assets_list.csv"
CRITICAL_ASSETS_COLUMN_NAMES = ["Hostname", 	
                                "IP Address",	
                                "System Owner",	
                                "Operating System", 
                                "Description"]

OUTPUT_FILE = "/home/vince/inputs_and_outputs/es_consolidated_assets.csv"
OUPUT_COLUMN_NAMES = ['ip', 
                        'mac', 
                        'nt_host', 
                        'dns', 
                        'owner', 
                        'priority', 
                        'lat', 
                        'long', 
                        'city',
                        'state',
                        'country', 
                        'bunit', 
                        'category',
                        'pci_domain', 
                        'is_expected',
                        'should_timesync', 
                        'should_update', 
                        'requires_av', 
                        'cim_entity_zone',
                        'function',
                        'os']

##
#standard asset consolidation
#ip,mac,nt_host,dns,owner,priority,lat,long,city,country,bunit,category,pci_domain,is_expected,should_timesync,should_update,requires_av,cim_entity_zone
##
# key fields:
#   ip
#   mac
#   nt_host
#   dns
#  



def read_csv_file(filepath, columnnames, keycolumn = [], setcolumn = [], delimiter=',', ):
    """
    Reads a .csv file, extracts specified fields, builds a list of dict objects with specified columnname as key.

    Arguments:
    filepath -- path to the .csv file.
    column_names -- specified column names to read
    keycolumn -- which column to be used as key
    setcolumn -- which column to be set to a set
    delimiter -- the delimiter used to split fields in the file

    Return:
    dict_dict -- a dict of dict objects with hostname as key. For example, 
    {'host1': {'Priority': 'High', 'ID': '132'}, 
     'host2': {'Priority': 'Critical', 'ID': '143'}, 
     'host3': {'Priority': 'Medium', 'ID': '456'}}  
    
    """
    
    # empty dictionary container
    dict_dict = {}
    # indicator of line 
    line_count = 0
    
    with open(filepath, mode='r', encoding="utf8", errors='ignore') as f:
        # read file into dictionary list
        csv_reader = csv.DictReader(f, delimiter=delimiter)
        
        for row in csv_reader:
            # check if all specified column_names are included in the file with the first record.
            if line_count == 0: 
                for col_name in columnnames:
                    if col_name not in row:
                        raise NameError(col_name + " cannot be found in [" + ", ".join(row) + "]")
            #print 'Column names read from file are [' + ", ".join(row) + ']'
            # update the field specified by set column to set
            if len(setcolumn) > 0:
                for sc in setcolumn:
                    s = row[sc]
                    row[sc]={s}
            
            # print the row  
            #print row
            # build key
#                key_str_list = [row[key.strip()] for key in keycolumn.split(",")]
#                combined_key_str = "-".join(key_str_list)
            combined_key_str = ""
            if len(keycolumn) > 1:
                key_str_list = [row[key] for key in keycolumn]
                combined_key_str = "-".join(key_str_list)
            else:
                combined_key_str = row[keycolumn[0]]
            
            # add row into dict_dict
            combined_key_str = combined_key_str.strip().lower()
            dict_dict[combined_key_str] = row
            # increase line
            line_count = line_count + 1
                            
        
    print("Successfully read {0} lines with {1} unique records by {3} from {2}".format(line_count, len(dict_dict), filepath, keycolumn[0]))
    #print(len(dict_dict))
    return dict_dict

def write_csv_file(filepath, column_names, new_id_list):
    """
    Write new identity list to a .csv file.

    Arguments:
    filepath -- path to the .csv file.
    column_names -- specified column names to write.
    new_id_list -- list of identities with updated priorities.
    
    """
    
    
    if sys.version_info >= (3,0,0):
        with open(filepath, mode='w', newline='', errors='ignore') as f:
            writer = csv.DictWriter(f, fieldnames=column_names)
            # print the header
            writer.writeheader()
            # print content line
            for id_dict in new_id_list:
                writer.writerow(id_dict)
    else:
        with open(filepath, mode='wb') as f:
            writer = csv.DictWriter(f, fieldnames=column_names)
            # print the header
            writer.writeheader()
            # print content line
            for id_dict in new_id_list:
                writer.writerow(id_dict)
                
    print("Successfully saved {0} records to {1}".format(len(new_id_list),filepath))



def print_list_string(str_list):
    '''
    print out list elements with "-" as dilimiters.
    
    '''
    str_list.sort()
    return "|".join(str_list)


def merge_dict_keys_by_host(tanium, field_to_merge ):
    """
    takes in a master dictionary - tanium - and creates another dictionary, merging targetted fields hence restructuring the 
    content of the original dictionary, making simpler 

    Arguments: 
    tanium:         dictionary we want to restructure. Key for dictionary is the hostname
    field_to_merge: fields we want to consolidate into a set from the tanium dictionary 
                    Let us assume this field is the IP field. 
                    then this method will return another dictionary, whose key is hostname and value is a set of all IPs for the given host. 

    return:
        {
            'wtc-1111111-l2' : {'199.182.161.2', '199.183.161.3'},
            .
            .
            'wtc-22222-W2' : {'199.182.161.5'}
        }   
    """
    merged_k_dict = {}
 
    for k,v in tanium.items():
        dict_key = tanium[k]['Computer_Name']
        dict_key = dict_key.strip().lower()
        
        if tanium[k]['Computer_Name'] and dict_key not in merged_k_dict:
            merged_k_dict[dict_key] = set()
            merged_k_dict[dict_key].add(tanium[k][field_to_merge])
        elif tanium[k]['Computer_Name'] and dict_key in merged_k_dict:
            merged_k_dict[dict_key].add(tanium[k][field_to_merge])
            
        
    return merged_k_dict

def callSplunkAPi(retry, url):
    """
    This method simply handles the rest call to splunk for getting tanium data
    Retry is handled recursively
    """
    
    payload = {}
    
    logging.basicConfig(filename='./logSplunkESAPICall.log', format=FORMAT, level=logging.DEBUG)
    logging.debug("username : {0}".format(username))
    logging.debug("search : {0}".format(search))
    logging.debug("timeout : {0}".format(timeout))
    logging.debug("url : {0}".format(url))
    payload['output_mode']='csv'
    payload['search']=search

    logging.info("About to make request")
    #response=''
    try:
        response = requests.request('POST', url, data=payload, auth=(username, password), verify=False, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(errh, retry+1))
            print("Exception {0} encountered, retry {1}".format(errh, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url)
        else:
            logging.error("Unable to get data")
    except requests.exceptions.ConnectionError as errc:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(errc, retry+1))
            print("Exception {0} encountered, retry {1}".format(errc, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url)
        else:
            logging.error("Unable to get data")
    except requests.exceptions.Timeout as errt:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(errt, retry+1))
            print("Exception {0} encountered, retry {1}".format(errt, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url)
        else:
            logging.error("Unable to get data")
    except requests.exceptions.RequestException as e:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(e, retry+1))
            print("Exception {0} encountered, retry {1}".format(e, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url)
        else:
            logging.error("Unable to get data")
    return response
    
def findOwner(host_name, fqdn_str, computer_appset_dict, app_dict, critical_assets_hostname_dict, critical_assets_ip_list, tanium_dict, ip_address):
    """
    host_name: 
    fqdn_str: 
    computer_appset_dict:
    app_dict:
    critical_assets_hostname_dict:
    tanium_dict: 
    ip_address: 

    """
    owner = ''
    #use hostname to try to find owner
    if host_name in computer_appset_dict:
        app_eai_id_set  = computer_appset_dict[host_name]
        app_eai_id_list = list(app_eai_id_set)
            
        # take the first app's owning_mgr as the owner
        first_available_app_eai = ''
        # find the first available eai
        for app_eai in app_eai_id_list:
            if app_eai in app_dict:
                first_available_app_eai = app_eai
                break
        

        if first_available_app_eai != '':
            if app_dict[first_available_app_eai]['u_owning_mgr'] != '': 
                owner = app_dict[first_available_app_eai]['u_owning_mgr']

            elif app_dict[first_available_app_eai]['it_application_owner'] != '':
                owner = app_dict[first_available_app_eai]['it_application_owner']

            elif app_dict[first_available_app_eai]['u_it_lead'] != '':
                owner = app_dict[first_available_app_eai]['u_it_lead']
    

    #use fqdn to check for asset ownership
    elif fqdn_str in computer_appset_dict:
        app_eai_id_set = computer_appset_dict[fqdn_str]
        app_eai_id_list = list(app_eai_id_set)
        
        # take the first app's owning_mgr as the owner
        first_available_app_eai = ''
        # find the first available eai
        for app_eai in app_eai_id_list:
            if app_eai in app_dict:
                first_available_app_eai = app_eai
                break
  
        if first_available_app_eai != '':
            if app_dict[first_available_app_eai]['u_owning_mgr'] != '': 
                owner = app_dict[first_available_app_eai]['u_owning_mgr']

            elif app_dict[first_available_app_eai]['it_application_owner'] != '':
                owner = app_dict[first_available_app_eai]['it_application_owner']

            elif app_dict[first_available_app_eai]['u_it_lead'] != '':
                owner = app_dict[first_available_app_eai]['u_it_lead']
    
    # as last resort if there is no value for owner from cmdb and the asset is critical we use the value from critical asset list 
    if host_name != "" and host_name in critical_assets_hostname_dict and owner =='':
        if critical_assets_hostname_dict[host_name]['System Owner'] != '' and critical_assets_hostname_dict[host_name]['System Owner'] != 'NA' :
            owner = critical_assets_hostname_dict[host_name]['System Owner']
    elif fqdn_str != "" and fqdn_str in critical_assets_hostname_dict and owner =='':
        if critical_assets_hostname_dict[fqdn_str]['System Owner'] != '' and critical_assets_hostname_dict[fqdn_str]['System Owner'] != 'NA' :
            owner = critical_assets_hostname_dict[fqdn_str]['System Owner']
    elif ip_address!="" and ip_address in critical_assets_ip_list:
        if critical_assets_ip_list[ip_address]['System Owner'] != '' and critical_assets_ip_list[ip_address]['System Owner'] !='NA' and owner =='':
            owner = critical_assets_ip_list[ip_address]['System Owner']

    #Tanium has a last user logged in - we could check tanium dict for last user logged in 
    
    return owner 

def getPriority(critical_assets_hostname_dict, critical_assets_ip_list, host_name, fqdn_str, ip_address):
    """
    critical_assets_hostname_dict: 
    critical_assets_ip_list: 
    host_name: 
    fqdn_str:  
    ip address

    """

    if host_name != "" and host_name in critical_assets_hostname_dict:
        matched_critical_hostname_set.add(host_name)
        return "critical"
        

    elif fqdn_str != "" and fqdn_str in critical_assets_hostname_dict:
        matched_critical_hostname_set.add(fqdn_str)
        return "critical"
        

    elif ip_address!="" and ip_address in critical_assets_ip_list:
        matched_critical_ip_set.add(ip_address)
        return "critical"
        
    else:
        return 'medium'

    
def getFunction(critical_assets_hostname_dict, critical_assets_ip_list, host_name, fqdn_str, ip_address):
    """
    critical_assets_hostname_dict: 
    critical_assets_ip_list: 
    host_name: 
    fqdn_str:  
    ip address

    """

    function=''
    if host_name != "" and host_name in critical_assets_hostname_dict:
        if critical_assets_hostname_dict[host_name]['Description'] !='' and critical_assets_hostname_dict[host_name]['Description'] !='NA':      
            function = critical_assets_hostname_dict[host_name]['Description']

    elif fqdn_str != "" and fqdn_str in critical_assets_hostname_dict:
        if critical_assets_hostname_dict[fqdn_str]['Description'] !='' and critical_assets_hostname_dict[fqdn_str]['Description'] !='NA':  
            function = critical_assets_hostname_dict[fqdn_str]['Description']

    elif ip_address!="" and ip_address in critical_assets_ip_list:
        if critical_assets_ip_list[ip_address]['Description'] != '' and critical_assets_ip_list[ip_address]['Description'] != 'NA':
            function = critical_assets_ip_list[ip_address]['Description']

    return function 

if __name__ == '__main__':
    
    start = time.time()
    retry=0

    start = time.time()

    #Step 1: make rest call to get tanium asset data - querying splunk tanium index for the last day
    #req = requests.request('POST', url, data=payload, auth=(username, password), verify=False, timeout=timeout)
    url = 'https://'+server+':'+port+'/services/search/jobs/export'
    req = callSplunkAPi(0, url)
    #req.raise_for_status()

    end = time.time()
    logging.info("Query ran in elapsed time {0} seconds.".format(end-start))
    logging.debug("response type {0}".format(type(req)))
    #write output to a filei

    logging.info("Writing output to a file")

    csv_file = open("/home/vince/inputs_and_outputs/tanium.csv", "wb")
    csv_file.write(req.content)
    csv_file.close()

    end = time.time()
    print("Writing to file took {0} seconds.".format(end-start))

    tanium_dict = read_csv_file(TANIUM_FILE, TANIUM_COLUMN_NAMES, keycolumn = ['Computer_Name'])

    # Step 0: read tanium assets and build build dictionary of macs 
    tanium_dict_full = read_csv_file(TANIUM_FILE, TANIUM_COLUMN_NAMES, keycolumn = ['Computer_Name', 'mac_address'])
    mac_dict = merge_dict_keys_by_host(tanium_dict_full, 'mac_address')       # key is hostname, value are mac addresses 
    
    #merge IPs
    
    ip_dict = merge_dict_keys_by_host(tanium_dict_full, 'IPv4_Address')        # key is hostname, value are IP addresses
    
    #merge dns
    dns_dict = merge_dict_keys_by_host(tanium_dict_full, 'Domain_Name')
    
    opco_dict = read_csv_file(OPCO_FILE, OPCO_COLUMN_NAMES, keycolumn=['opco'])

    # Step 1: read computers
    computer_dict = read_csv_file(COMPUTER_FILE, COMPUTER_COLUMN_NAMES, keycolumn = ['name'])
#    end = time.time()
#    print("Elapsed time {0} seconds.".format(end-start))
    
    # Step 2: read apps
    app_dict = read_csv_file(APP_FILE, APP_COLUMN_NAMES, keycolumn = ['u_eai_id'])
    
    # Step 3: read mapping 
    mapping_list = read_csv_file(MAPPING_FILE, MAPPING_COLUMN_NAMES, keycolumn = ['child'])
    
    # Step 4: read critical assets
    critical_assets_hostname_dict = read_csv_file(CRITICAL_ASSETS_FILE, CRITICAL_ASSETS_COLUMN_NAMES, keycolumn= ['Hostname'])
    # Step 5: read critical assets ips
    critical_assets_ip_list = read_csv_file(CRITICAL_ASSETS_FILE, CRITICAL_ASSETS_COLUMN_NAMES, keycolumn= ['IP Address'])

    static_assets_hostname = read_csv_file(STATIC_ASSETS_FILE, STATIC_ASSETS_COLUMN_NAMES, keycolumn= ['ip', 'dns'])

    scanner_assets_hostname = read_csv_file(SCANNER_FILE, SCANNER_COLUMN_NAMES, keycolumn= ['ip','dns'])

    
    
     # Step 4: use the mapping list to generate compute_app_list
    computer_appset_dict = {}
    processed_cmpters = {}

    for k, v in mapping_list.items():
        if k not in computer_appset_dict:
            computer_appset_dict[k] = set()
            computer_appset_dict[k].add(v['parent.ref_cmdb_ci_business_app.u_eai_id'])
        else:
            computer_appset_dict[k].add(v['parent.ref_cmdb_ci_business_app.u_eai_id'])
            
    print("CMDB_CI_REL file constains eai record for {0} unique computers.".format(len(computer_appset_dict)))
    
    new_asset_list = []
    unique_asset_set = set()
    filtered_count = 0
    # contain all matched
    #matched_critical_hostname_set =  set()
    #matched_critical_ip_set =  set()
    
    # Step 5: loop through cmdb computer assets and add to consolidated list 
    for cmp_key, cmp_value in computer_dict.items(): 
        ## Filter out records with all empty of 'name', 'fqdn', and 'ip_address' 
        #if cmp_value['fqdn'] == "" and cmp_value['ip_address'] == "":
        if cmp_value['name'] == "" and cmp_value['ip_address'] == "":
            filtered_count = filtered_count + 1
            continue
        
        if cmp_key not in unique_asset_set:
            unique_asset_set.add(cmp_key)
        
        # build a new asset dict
        new_asset = {}
        fqdn_str  = ""
        host_name = ""
        if cmp_value['fqdn']:
            fqdn_str            = cmp_value['fqdn']

        elif cmp_value['name'] and cmp_value['dns_domain']:
            fqdn_str            = cmp_value['name']+"."+cmp_value['dns_domain']

        fqdn_str                = fqdn_str.strip().lower()
        host_name               = cmp_value['name']
        host_name               = host_name.strip().lower()
        new_asset['nt_host']    = host_name # first part of fqdn
        #host_name               = fqdn_str.split(".")[0]
        
        #check if using the fqdn, hostname or name (column from cmdb) as key we get a match within one of the follow matches in the ip, mac and dns dictionary
        ip              = cmp_value['ip_address']
        new_asset['ip'] = ip
        
        #get consolidated macs
        if fqdn_str in mac_dict:
            if cmp_value['mac_address'] and cmp_value['mac_address'] not in mac_dict[fqdn_str]:
                mac_dict[fqdn_str].add(cmp_value['mac_address'])
            
            macs = '|'.join(str(s) for s in mac_dict[fqdn_str])
            new_asset['mac'] = macs
            #new_asset['mac'] = mac_dict[cmp_value['fqdn']]
        elif host_name in mac_dict:
            if cmp_value['mac_address'] and cmp_value['mac_address'] not in mac_dict[host_name]:
                mac_dict[host_name].add(cmp_value['mac_address'])

            macs = '|'.join(str(s) for s in mac_dict[host_name])
            new_asset['mac'] = macs
        #elif cmp_key in mac_dict:
        #        macs = ' | '.join(str(s) for s in mac_dict[cmp_key])
        #        new_asset['mac'] = macs
        elif cmp_value['u_mac'] and cmp_value['mac_address']:
            new_asset['mac'] = cmp_value['u_mac']+"|"+cmp_value['mac_address']

        elif cmp_value['u_mac']:
            new_asset['mac'] = cmp_value['u_mac']

        elif cmp_value['mac_address']:  
            new_asset['mac'] = cmp_value['mac_address'] 
        else:
            new_asset['mac'] = ''
        
        
        #get consolidated domains
        new_asset['dns'] = fqdn_str.replace('[current result unavailable]', '')
        ###=========== Set owner - the app list =================
        new_asset['owner'] = ''
        owner = findOwner(host_name, computer_appset_dict, app_dict, critical_assets_hostname_dict, critical_assets_ip_list, tanium_dict, cmp_value['ip_address'] )
        if owner != '':
            new_asset['owner'] = owner
        else:
            new_asset['owner'] = cmp_value['managed_by'] 

        ###===========determine criticality==========
        criticality = getPriority(critical_assets_hostname_dict, critical_assets_ip_list, host_name, fqdn_str, cmp_value['ip_address'])

        new_asset['priority'] = criticality

        asset_function = getFunction(critical_assets_hostname_dict, critical_assets_ip_list, host_name, fqdn_str, cmp_value['ip_address'])
        new_asset['function'] = asset_function
        new_asset['lat'] = ''
        new_asset['long'] = ''

        if cmp_value['location.city']:
            new_asset['city'] = cmp_value['location.city']

        if cmp_value['location.state']:
            new_asset['state'] = cmp_value['location.state']

        if cmp_value['location.u_country_ref']:
            new_asset['country'] = cmp_value['location.u_country_ref']
        elif fqdn_str in tanium_dict:
            new_asset['country'] = tanium_dict[fqdn_str]['os_country_code_name']
        elif host_name in tanium_dict:
            new_asset['country'] = tanium_dict[host_name]['os_country_code_name']
        
        if "[" not in cmp_value['os'] and "]" not in cmp_value['os'] and "TSE-Error" not in cmp_value['os']:
            new_asset['os'] = cmp_value['os']

        if cmp_value['u_managing_opco'].strip().lower() in opco_dict:
            new_asset['bunit'] = opco_dict[cmp_value['u_managing_opco'].strip().lower()]['normalize']
        else:
            new_asset['bunit'] = cmp_value['u_managing_opco']
        new_asset['category'] = cmp_value['sys_class_name']
        new_asset['pci_domain'] = ''
        new_asset['is_expected'] = ''
        new_asset['should_timesync'] = ''
        new_asset['should_update'] = ''
        new_asset['requires_av'] = ''
        #new_asset['source'] = 'cmdb'
        
        # after update, add to the new list
        new_asset_list.append(new_asset)
        processed_cmpters[host_name]    = host_name
    
    print("There are {0} invalid records skipped.".format(filtered_count))
    print("There are {0} critical assests matched with cmdb assets.".format(len(matched_critical_hostname_set) + len(matched_critical_ip_set)))
    
    # Step 6
    # Now run through Tanium Assets to identify assets in tanium that arent in cmdb and add to es consolidated list        
    for k,v in tanium_dict.items():
        if '.' in k:
            hostname = k.split('.',1)[0]
            hostname = hostname.strip().lower()
        else:
            hostname = k
            hostname = hostname.strip().lower() 

        if hostname not in processed_cmpters:
            if not(v['Computer_Name'] and v['IPv4_Address']):
                filtered_count = filtered_count + 1
                        
            if hostname not in unique_asset_set:
                unique_asset_set.add(hostname)
    
            new_asset = {}
            fqdn_str  = ""
            # get fully qualified domain name
            fqdn_str            = v['Computer_Name']
            fqdn_str            = fqdn_str.strip().lower()
            
            host_name               = fqdn_str.split('.',1)[0]
            new_asset['nt_host']    = host_name # first part of fqdn
            
            #check if using the fqdn, hostname or name (column from cmdb) as key we get a match within one of the follow matches in the ip, mac and dns dictionary
            new_asset['ip'] = v['IPv4_Address']

            #retrieve consolidated macs   
            if fqdn_str in mac_dict:
                macs = '|'.join(str(s) for s in mac_dict[fqdn_str])
                new_asset['mac'] = macs
                
            elif host_name in mac_dict:
                    macs = '|'.join(str(s) for s in mac_dict[host_name])
                    new_asset['mac'] = macs

            else:
                new_asset['mac'] = ''
            
            #retrieve consolidated dns
            #if there is a dot in fqdn and the str before the first dot isnt a digit - trying to disclude IP addresses - then make fqdn dns
            if "." in fqdn_str and (not host_name.isdigit()):
                new_asset['dns'] = fqdn_str

            elif "." not in fqdn_str and v['Domain_Name']:
                new_asset['dns'] = fqdn_str+v['Domain_Name']
           
            #=========== Retrieve Asset Owner =================
            new_asset['owner'] = ''
            owner = findOwner(host_name, computer_appset_dict, app_dict, critical_assets_hostname_dict, critical_assets_ip_list, tanium_dict, v['IPv4_Address'])
            if owner != '':
                new_asset['owner'] = owner

            ###=========== check critical==========
            criticality = getPriority(critical_assets_hostname_dict, critical_assets_ip_list, host_name, fqdn_str, v['IPv4_Address'])
            new_asset['priority'] = criticality

            asset_function = getFunction(critical_assets_hostname_dict, critical_assets_ip_list, host_name, fqdn_str, v['IPv4_Address'])
            new_asset['function'] = asset_function

            new_asset['lat'] = ''
            new_asset['long'] = ''
            new_asset['city'] = ''
            new_asset['country'] = v['os_country_code_name']
            new_asset['bunit'] = ''
            new_asset['category'] = v['os_platform']
            new_asset['os'] = v['operating_system']
            new_asset['pci_domain'] = ''
            new_asset['is_expected'] = ''
            new_asset['should_timesync'] = ''
            new_asset['should_update'] = ''
            new_asset['requires_av'] = ''
            #new_asset['source'] = 'tanium'
            # after update, add to the new list
            new_asset_list.append(new_asset)
            processed_cmpters[host_name]    = host_name
    
    print("There are {0} invalid records skipped.".format(filtered_count))
    print("There are {0} critical assests matched in cmdb and tanium.".format(len(matched_critical_hostname_set) + len(matched_critical_ip_set)))

    #Step 7: Go through critical assets and add critical assets that arent in cmdb or tanium
    # Add unmatched crtical assetts the the new assets list
    n_count=0
    for k, v in critical_assets_hostname_dict.items():
        hostname=k
        if "." in hostname:
            hostname=k.split(".", 1)[0]
            hostname=hostname.strip().lower()
        
        if (hostname not in processed_cmpters ) and (v['IP Address'] not in matched_critical_ip_set) :
            n_count = n_count +1
            if hostname not in unique_asset_set:
                unique_asset_set.add(hostname)
             # build a new asset dict
            new_asset = {}
            if "DHCP" not in v['IP Address'] and "NA" not in v['IP Address'] and "N/A" not in v['IP Address']:
                new_asset['ip'] = v['IP Address']
            else:
                new_asset['ip'] = " "
                
            new_asset['mac'] = ''
            #host = v['Hostname'].strip().lower()
            new_asset['nt_host'] = hostname
            if "." in v['Hostname'] and (not hostname.isdigit()):
                new_asset['dns'] = v['Hostname']
            
            if v['System Owner'] != 'NA':
                new_asset['owner'] = v['System Owner']

            new_asset['priority'] = "critical"

            if v['Description'] != 'NA':
                new_asset['function'] = v['Description']

            if v['Operating System'] != 'NA':    
                new_asset['os'] = v['Operating System']

            new_asset['lat'] = ''
            new_asset['long'] = ''
            new_asset['city'] = ''
            new_asset['country'] = ''
            new_asset['bunit'] = ''
            new_asset['pci_domain'] = ''
            new_asset['is_expected'] = ''
            new_asset['should_timesync'] = ''
            new_asset['should_update'] = ''
            new_asset['requires_av'] = ''
            #new_asset['source'] = 'critical assets'
            
            new_asset_list.append(new_asset)
            processed_cmpters[hostname]    = hostname

    print("{0} critical assets have been added that weren't matched in cmdb or tanium.".format(n_count))

    #Step 8
    #Add all static assets to this csv
    n_count=0
    for k, v in static_assets_hostname.items():
        hostname = v['hostname'].strip().lower()
        fqdn_str = v['dns'].strip().lower()

        if hostname not in processed_cmpters:
            n_count = n_count +1
            if hostname not in unique_asset_set:
                unique_asset_set.add(hostname)
             # build a new asset dict
            new_asset = {}
            new_asset['ip'] = v['ip']
            new_asset['mac'] = ''
            new_asset['nt_host'] = hostname
            new_asset['dns'] = v['dns']
            
            owner = findOwner(hostname, fqdn_str, computer_appset_dict, app_dict, critical_assets_hostname_dict, critical_assets_ip_list, tanium_dict, v['ip'])
            new_asset['owner'] = owner

            new_asset['priority'] = "medium"
            new_asset['function'] = v['devicetype']
            if v['os']:
                new_asset['os'] = v['os']
            elif v['os_domain']:
                new_asset['os'] = v['os_domain']
            new_asset['category'] = v['category']
            new_asset['lat'] = ''
            new_asset['long'] = ''
            new_asset['city'] = ''
            new_asset['country'] = ''
            new_asset['bunit'] = v['opco']
            new_asset['pci_domain'] = ''
            new_asset['is_expected'] = ''
            new_asset['should_timesync'] = ''
            new_asset['should_update'] = ''
            new_asset['requires_av'] = ''
            #new_asset['source'] = 'static_assets'
            
            new_asset_list.append(new_asset)
            processed_cmpters[hostname]    = hostname

    print("{0} static assets have been added to es consolidated.".format(n_count))

    #Step 8
    #Add all static assets to this csv
    n_count=0
    for k, v in scanner_assets_hostname.items():
        hostname = v['dns'].strip().lower() 
        fqdn_str = v['dns'].strip().lower()  
        

        if "." in hostname:
            hostname=hostname.split(".", 1)[0].strip().lower()  #paranoia  

        if hostname not in processed_cmpters:
            n_count = n_count +1
            if hostname not in unique_asset_set:
                unique_asset_set.add(hostname)
            new_asset = copy.deepcopy(v)
            new_asset['priority'] = "medium"
            #new_asset['source'] = 'scanner_assets'
            owner = findOwner(hostname, fqdn_str, computer_appset_dict, app_dict, critical_assets_hostname_dict, critical_assets_ip_list, tanium_dict, v['ip'])
            new_asset['owner'] = owner
            new_asset_list.append(new_asset)
            processed_cmpters[hostname]    = hostname

    print("{0} scanner assets have been added to es consolidated.".format(n_count))

    # Step 9: save file
    write_csv_file(OUTPUT_FILE, OUPUT_COLUMN_NAMES, new_asset_list)
    print("There are {0} unique items in es consolidated file.".format(len(unique_asset_set)))
    end = time.time()
    print("Elapsed time {0} seconds.".format(end-start))

