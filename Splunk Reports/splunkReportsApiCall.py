# -*- coding: utf-8 -*-
"""
Created on Jan 28, 2021
@author: Vince Nkawu 
@email:  nkawuv@gmail.com
"""


import configparser
import logging
import time
import requests
from datetime import date, timedelta
import sys
import urllib.parse
import xml.etree.ElementTree as ET
#import xml.etree.Element as E
#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Initialize global variables
retries=5
"""
FORMAT = ''
logging.basicConfig(filename='logs/logUEBAReportsApiCall.log', format=FORMAT, level=logging.DEBUG)
retries=5
config = configparser.ConfigParser()

url = '' 
username = ''
password = ''
timeout = '' 
timeout  = '' 
savedSearchHistoryUrl = ''
searchJobs = '' 
savedSearches = ''
"""

def callSplunkAPi(retry, url, username, password, timeout, payload={}):
    """
    This method simply handles the rest call to splunk for getting saved searches/reports
    Retry is handled recursively
    """
    
    logging.debug("url : {0}".format(url))
    logging.debug("payload : {0}".format(payload))
    logging.info("About to make request")
    response=''
    try:
        if len(payload)>0:
            response = requests.request('GET', url, params=payload, auth=(username, password), verify=False, timeout=timeout)
        else:
            response = requests.request('GET', url, auth=(username, password), verify=False, timeout=timeout)

        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(errh, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url, username, password, timeout, payload)
        else:
            logging.error("Unable to get data")
    except requests.exceptions.ConnectionError as errc:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(errc, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url, username, password, timeout, payload)
        else:
            logging.error("Unable to get data")
    except requests.exceptions.Timeout as errt:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(errt, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url, username, password, timeout, payload)
        else:
            logging.error("Unable to get data")
    except requests.exceptions.RequestException as e:
        if retry<retries:
            logging.warn("Exception {0} encountered, retry {1}".format(e, retry+1))
            retry = retry + 1
            response = callSplunkAPi(retry, url, username, password, timeout, payload)
        else:
            logging.error("Unable to get data")
    return response


def getReport(propertyFile):

    start = time.time()
    propertyFilePath = propertyFile    
    #read application properties from properties file
    FORMAT = '%(asctime)-15s: %(levelname)s:  %(message)s'
    if '/' in propertyFile:
        propertyFile = propertyFile.split('/')
        propertyFile = propertyFile[len(propertyFile)-1]        
    
    logging.basicConfig(filename='/opt/scripts/batch-mode/logs/' + propertyFile.split('.')[0] + 'ApiCall.log', format=FORMAT, level=logging.DEBUG)
    retries=5
    config = configparser.ConfigParser()
    config.read(propertyFilePath)

    #read properties from a property file
    url = config.get('splunkProperties','splunk.url')
    username = config.get('splunkProperties','splunk.username')
    password = config.get('splunkProperties','splunk.password')
    timeout = config.get('splunkProperties','splunk.timeout')
    timeout  = int(timeout)
    savedSearchHistoryUrl = config.get('splunkProperties','splunk.url.savedSearchHistory')
    searchJobs = config.get('splunkProperties','splunk.url.searchJobs')
    savedSearches = config.get('splunkProperties','splunk.saved.searches')
    savedSearches = savedSearches.split(',')        #titles of saved searches we want to get report for

    logging.debug("username : {0}".format(username))
    logging.debug("timeout setting : {0}".format(timeout))    
    
    #trim leading and trailing spaces from saved Searches
    savedSearchList=[] 
    for i in savedSearches:
        savedSearchList.append(urllib.parse.quote(i.strip()))
    
    #
    i=0
    for searchName in savedSearches:
        encodedSearchName = urllib.parse.quote(searchName.strip())
        url = savedSearchHistoryUrl+encodedSearchName+"/history"
        payload={}
        payload['count']=1                                          #we just want to retrieve the last ran search so only one needed if we sort by desc order
        payload['sort_dir']='desc'
        i=i+1
        logging.info("Get report [{0}] : {1}".format(i, searchName))
        logging.info("call history api to GET SID for last ran report") 
        resp = callSplunkAPi(0, url, username, password, timeout, payload)
               
        root = ET.fromstring(resp.text)
        title=''
  
        for entry in root.findall('{http://www.w3.org/2005/Atom}entry'):
            title = entry.find('{http://www.w3.org/2005/Atom}title').text  #capture title of latest report used to make another api call to get result
        if title and 'scheduler' in title:
            logging.debug("scheduled report title (SID): {0}".format(title))
            logging.info("call results api to get result of last ran report")
            savedSearchReportURL = searchJobs+title+"/results"
            payload={}
            payload['output_mode']='csv'
            payload['count']=0
            resultResp = callSplunkAPi(0, savedSearchReportURL, username, password, timeout, payload)
            
            if resultResp.text:
                reportFileName = searchName.strip().replace(' ','_')+".csv"
                csv_file = open("/opt/scripts/batch-mode/saved_searches/"+reportFileName, "wb")
                csv_file.write(resultResp.content)
                csv_file.close()
                logging.debug("Saved report [{0}] to {1}".format(i, reportFileName))
            elif not resultResp.text and title:
                logging.debug("There were 0 events in last report, nothing saved")

             
        else:
            logging.debug('Nothing to save - There is no history for this report, no sid could be retrieved for the last ran report')

    #req.raise_for_status()

    end = time.time()
    logging.info("Query ran in elapsed time {0} seconds.".format(end-start))

if __name__ == '__main__':
    #pass in the property file we will use to determine what reports we need to extract and get variables needed for the script
    if len(sys.argv) < 2 or len(sys.argv) > 2:
        print("Script expects an argument for property file")
        print("Usage: splunkReportsApiCall.py <propertyfile>")
    if len(sys.argv) == 2:
        propertyFile=sys.argv[1].strip()
        print(propertyFile)
        getReport(propertyFile)

