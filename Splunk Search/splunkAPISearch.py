# -*- coding: utf-8 -*-
"""
Created on Jan 12, 2021
@author: Vince Nkawu
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
retries=5
config = configparser.ConfigParser()
config.read('/home/vince/inputs_and_outputs/app.properties')

url = config.get('splunkProperties','splunk.url')
username = config.get('splunkProperties','splunk.username')
password = config.get('splunkProperties','splunk.password')
search = config.get('splunkProperties','splunk.search')
timeout = config.get('splunkProperties','splunk.timeout')
timeout  = int(timeout)


CS_COLUMN = ['title', 'search']
ON_PREM_FILE = "./corellation_search/onPrem_CS.csv"
CLOUD_FILE = "./corellation_search/cloud_CS.csv"
"""
format of above csv
    
title, search, time
"""

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
    dict_dict -- a dict of dict objects with ID as key. For example, 
    {'132': {'Priority': 'High', 'ID': '132'}, 
     '143': {'Priority': 'Critical', 'ID': '143'}, 
     '456': {'Priority': 'Medium', 'ID': '456'}}  
    
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


def callSplunkAPi(retry, url, payload):

    logger.info("About to make request")
    print("-----------------------------\nPayload: {0}\n-------------------------".format(payload))
    #response=''
    try:
        response = requests.request('POST', url, data=payload, auth=(username, password), verify=False, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(errh, retry+1))
            print("Exception {0} encountered, retry {1}".format(errh, retry+1))
            time.sleep(10)
            retry = retry + 1
            response = callSplunkAPi(retry, url, payload)
        else:
            logger.error("Unable to get data")
    except requests.exceptions.ConnectionError as errc:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(errc, retry+1))
            print("Exception {0} encountered, retry {1}".format(errc, retry+1))
            time.sleep(10)
            retry = retry + 1
            response = callSplunkAPi(retry, url, payload)
        else:
            logger.error("Unable to get data")
    except requests.exceptions.Timeout as errt:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(errt, retry+1))
            print("Exception {0} encountered, retry {1}".format(errt, retry+1))
            time.sleep(10)
            retry = retry + 1
            response = callSplunkAPi(retry, url, payload)
        else:
            logger.error("Unable to get data")
    except requests.exceptions.RequestException as e:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(e, retry+1))
            print("Exception {0} encountered, retry {1}".format(e, retry+1))
            time.sleep(10)
            retry = retry + 1
            response = callSplunkAPi(retry, url, payload)
        else:
            logger.error("Unable to get data")
    return response
    
if __name__ == '__main__':
    
    start = time.time()
    retry=0
    
    #create logging properties 
    logger = logging.getLogger('CSlogs')
    FORMAT = logging.Formatter('%(asctime)-15s: %(levelname)s:  %(message)s')
    open('./corellation_search/logCorellationSearchAPICall.log', 'a').close()
    fh = logging.FileHandler('./corellation_search/logCorellationSearchAPICall.log')
    fh.setFormatter(FORMAT)
    logger.addHandler(fh)
    
    logger.info("About to make request")
    start = time.time()
    
    #read searches from csv files
    onprem_CS_dict = read_csv_file(ON_PREM_FILE, CS_COLUMN, keycolumn=['title'])
    cloud_CS_dict =  read_csv_file(CLOUD_FILE, CS_COLUMN, keycolumn=['title'])
    i = 0
    for k,v in onprem_CS_dict.items():
        print("Title: {0}\nSearch: {1}".format(k, v['search'].replace('\n','')))
        print("\n------------------------------------------------------------------------------------------------------\n")
        
        payload = {}
        payload['output_mode']='csv'
        if v['search'].strip().startswith('|'):
            payload['search']= v['search'].strip().replace('\n','')
        else:
            payload['search']="search "+v['search'].strip().replace('\n','')
        
        payload['earliest_time'] =v['time'].strip()

        req = callSplunkAPi(0, url, payload)
        req.raise_for_status()

        end = time.time()
        logger.info("Query ran in elapsed time {0} seconds.".format(end-start))
        logger.debug("response type {0}".format(type(req)))
        #write output to a filei

        logger.info("Writing output to a file")

        csv_file = open("/home/vince/corellation_search/OnPrem_"+k.replace(' ','_')+".csv", "wb")
        csv_file.write(req.content)
        csv_file.close()
        i=i+1
    
