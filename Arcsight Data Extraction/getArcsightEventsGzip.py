# -*- coding: utf-8 -*-
"""
Created on November 19, 2021
@author:    Vince Nkawu
@email :    nkawuv@gmail.com
"""

import gzip, shutil
import logging
import time
import json
import requests
from datetime import timedelta, datetime
import re
import os, threading
import io
import sys
import time
#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings()

#logging config
logger = logging.getLogger('logs')
logger.setLevel(logging.DEBUG)
errorLogger = logging.getLogger('errors')
errorLogger.setLevel(logging.ERROR)
replayLogger = logging.getLogger('replay')
replayLogger.setLevel(logging.ERROR)



def callArcsightAPi(retry, url, delay, retries, payload={}, headers={}):
    """
    This method simply handles the rest call to arcsight for getting saved searches/reports
    Retry is handled recursively
    """

    logger.debug("url : {0}".format(url))
    #logger.debug("payload : {0}".format(payload))
    logger.info("About to make request")
    #response=''
    apiCallStart = time.time()

    try:
        if "search" not in url:
            #logger.debug(payload)
            response = requests.request('POST', url, data=payload, verify=False, headers=headers)
        else:
            #logger.debug(payload)
            response = requests.request('POST', url, json=payload, verify=False, headers=headers)
   
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(errh, retry+1))
            retry = retry + 1
            time.sleep(delay*retry)
            response = callArcsightAPi(retry, url, delay, retries, payload, headers)
        else:
            logger.error("Unable to get data")
    except requests.exceptions.ConnectionError as errc:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(errc, retry+1))
            retry = retry + 1
            time.sleep(delay*retry)
            response = callArcsightAPi(retry, url, delay, retries, payload, headers)
        else:
            logger.error("Unable to get data")
    except requests.exceptions.Timeout as errt:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(errt, retry+1))
            retry = retry + 1
            time.sleep(delay*retry)
            response = callArcsightAPi(retry, url, delay, retries, payload, headers)
        else:
            logger.error("Unable to get data")
    except requests.exceptions.RequestException as e:
        if retry<retries:
            logger.warn("Exception {0} encountered, retry {1}".format(e, retry+1))
            retry = retry + 1
            time.sleep(delay*retry)
            response = callArcsightAPi(retry, url, delay, retries, payload, headers)
        else:
            logger.error("Unable to get data")
    
    apiCallEnd = time.time()
    logger.info("Api call to - {1} - ran in: {0} s".format(round(apiCallEnd-apiCallStart, 2), url))

    return response


def createSearch(startTime, endTime, session, token, server, port, localsearch, delay, retries): 
    """
    Use this method to create a search session    
    """   
    url = "https://"+server+":"+port+"/server/search"

    payload={}
    payload['search_session_id'] = session
    payload['user_session_id'] =  token
    payload['discover_fields'] = False
    payload['end_time'] =  endTime+".000Z"
    payload['summary_fields'] =  ["Event Time", "Device", "Logger", "Raw Message"]
    payload['field_summary'] =  False 
    payload['local_search'] =  localsearch
    payload['query'] =  "(deviceVendor != \"ArcSight\")"
    payload['search_type'] = "interactive"
    payload['start_time'] = startTime+".000Z"
    payload['timeout'] = 1800000


    headers = {}
    headers['Accept'] = 'application/json'
    headers['Content-Type'] = 'application/json'



    resp = callArcsightAPi(0, url, delay, retries, payload, headers)
    resp.raise_for_status
    sessionId=''
    try: 
        if resp.status_code == 200:
            sessionId = resp.json()["sessionId"]
            logger.debug("Session id: {0}".format(sessionId))
            return 0 #indicate search successfully created
    except ValueError as e:
        errorLogger.error("{0}: when trying to create search. Search may have failed".format(e))
        return 1 #indicate search failed to create        

def authentication(server, port, username, password, delay, retries):
    """
    authenticate and get token from logger 
    """
    url = "https://"+server+":"+port+"/core-service/rest/LoginService/login"
    logger.info(url)
    payload = {}
    payload['login'] = username
    payload['password'] = password

    headers = {}
    headers['Accept'] = 'application/json'
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    
    resp = callArcsightAPi(0, url, delay, retries, payload,headers)

    try:
        token = resp.json()['log.loginResponse']['log.return']
        logger.debug(token)
    except ValueError as e:
        errorLogger.error("{0} when evaluating response from authentication".format(e))
            
    return token


def checkStatus(token, session, server, port, delay, retries):
    """
    check result status of running search to see if it is completed

    """
    
    url = "https://"+ server + ":" + port + "/server/search/status"
    payload={}
    payload["search_session_id"] = session
    payload["user_session_id"] =  token

    headers = {}
    headers['Accept'] = 'application/json'
    headers['Content-Type'] = 'application/json'
 
    hit=0
    
    status = "running"
    while status!="complete":
        resp = callArcsightAPi(0, url, delay, retries, payload,headers)

        try:
            status = resp.json()["status"]
            hit = resp.json()["hit"]
            scanned = resp.json()["scanned"]
            logger.info("status : {0}".format(status))
            logger.info("hit : {0}".format(hit))
            logger.info("scanned : {0}".format(scanned))
            if "error" in status:
                break
        except ValueError as e:
            errorLogger.error("{0}: when checking status".format(e))
        except Exception as e:
            errorLogger.error("{0}: when checking status".format(e))

        if status!="complete":
            logger.info("Delay {0} sec and reacheck status".format(delay*2))
            time.sleep(delay*2)

    return hit

def getEvents(token, session, offset, server, port, increments, delay, retries, strStartTime, strEndTime):
    #get events
    url = "https://" + server + ":" + port + "/server/search/events"
    payload={}
    payload["search_session_id"] = session
    payload["user_session_id"] =  token
    payload["dir"] = "forward"
    payload["length"] =  increments
    payload["offset"] = offset

    headers = {}
    headers['Accept'] = 'application/json'
    headers['Content-Type'] = 'application/json'

    resp = callArcsightAPi(0, url, delay, retries, payload,headers)
    rowIds=[]

    try:
        if "results" in resp.json(strict=False):
            results = resp.json(strict=False)["results"]
            rowIds = []
            for result in results:
                    #logger.info([result[0]])
                    rowIds.append(result[0])

        else:
            logger.info(resp.content)
            rowIds.append("empty")
    except ValueError as e:
        errorLogger.error("{0}: during window {1} to {2} and offset {3}".format(e, strStartTime, strEndTime, offset))
    except Exception as e:
        errorLogger.error("{0}: during window {1} to {2} and offset {3}".format(e, strStartTime, strEndTime, offset))
    
    return rowIds
    #logger.info(resultList)

#get raw events
def getCEFs(token, session, resultList, server, port, delay, retries):
    url = "https://"+server+":"+port+"/server/search/raw_events"
    payload={}
    payload["search_session_id"] = session
    payload["user_session_id"] =  token
    payload["row_ids"] = resultList

    headers = {}
    headers['Accept'] = 'application/json'
    headers['Content-Type'] = 'application/json'
    
    resp = callArcsightAPi(0, url, delay, retries, payload,headers)
    try:
        cefResults = resp.json(strict=False)
    except ValueError as e:
        errorLogger.error("{0}: when getting json response from raw events api".format(e))
    except Exception as e:
        errorLogger.error("{0}: when getting json response from raw events api".format(e))

    return cefResults


def beginDataExtraction(server,port,startTime,endTime, initialTimedeltaMins, username, password, delay, retries, baseEventDir, seedsession):
    #Authenticate once
    token = authentication(server, port, username, password, delay, retries)
    
    #initialize session
    session=seedsession

    #while loop keeps running till we get all data
    while startTime < endTime:
        finalTimeDetla = initialTimedeltaMins
        secs = 60
        start = time.time()
        strStartTime = startTime.strftime("%Y-%m-%dT%H:%M:%S") 
        strEndTime = (startTime + timedelta(minutes=initialTimedeltaMins)).strftime("%Y-%m-%dT%H:%M:%S") 
        logger.info("retrieve data from {0} to {1}".format(strStartTime, strEndTime))
        
        session=session+1
        localsearch=True

        #create search
        isSearchCreated = createSearch(strStartTime, strEndTime, session, token, server, port, localsearch, delay, retries)
        if isSearchCreated == 0:  
            logger.info("Search created on {0}".format(server))
            hit = checkStatus(token, session, server, port, delay, retries)

            while hit >= 1000000:
                logger.info("search hit 1,000,000 limit - Re-run with a shorter time window")

                if finalTimeDetla > 1:  # reduce time window by 1 min
                    finalTimeDetla = finalTimeDetla - 1
                    strEndTime = (startTime + timedelta(minutes=finalTimeDetla)).strftime("%Y-%m-%dT%H:%M:%S")

                elif finalTimeDetla == 1 and secs > 10:        #if mins delta is 1 then we start deducting by order of seconds instead of minutes
                    secs = secs - 10
                    strEndTime = (startTime + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")

                elif finalTimeDetla == 1 and secs < 10 and secs > 1:        #if mins delta is 1 then we start deducting by order of seconds instead of minutes
                    secs = secs - 1
                    strEndTime = (startTime + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")

                logger.info("retrieve data from {0} to {1}".format(strStartTime, strEndTime))
                isSearchCreated = createSearch(strStartTime, strEndTime, session, token, server, port, localsearch, delay, retries)
                
                #to deal with a bug in arcsight 
                if isSearchCreated == 0: 
                    logger.info("Search created on {0}".format(server))
                    hit = checkStatus(token, session, server, port, delay, retries)
                else:
                    time.sleep(delay*12)

            logger.info("Search completed - Total number of hits {0}".format(hit))
        
        
            #Define where we start getting data from (offset) and how much data to get at a time (increments)
            offset=0
            increments=10000
        
            basedir = baseEventDir + str(startTime.year) + "/" + str(startTime.month) + "/" + str(startTime.day) + "/"
            filepath = basedir + server.split('.')[0] + "_" + strStartTime.replace(':','_') + "__to__" + strEndTime.replace(':','_') + ".log"
            if not os.path.exists(basedir):
                os.makedirs(basedir)
        
            #for python 2.6.6 use:
            #with io.open(filepath, mode='w', errors='ignore') as f:

            f = gzip.open(filepath+".gz", mode='wb')
            while (hit-offset) > 0:            
                rowIds=[]
                logger.info("Processing events {0} - {1}".format(offset, offset+increments))
                rowIds = getEvents(token, session, offset, server, port, increments, delay, retries, strStartTime, strEndTime)
                
                #this is a break fix for an issue we saw w the logger where itll report so many hits but in actuality events were less than hits, so when we try to get the next set of hits, it would return an empty list of events
                if len(rowIds) > 0:
                    if "empty" in rowIds[0]:
                        break;
                logger.info("Retrieved rowIds")
                cefResults=getCEFs(token, session, rowIds, server, port, delay, retries)
                logger.info("{0} records retrieved so far".format(offset+len(cefResults)))
                offset=offset+len(rowIds)    # better to replace increments w len of cefResults
                for cefItem in cefResults:
                    f.write(cefItem.encode('utf-8') + "\n")
            f.close() 
             
            logger.info("file contains ** {0} ** lines".format(offset))
            
            end=time.time()
            logger.info("Finish retrieving data btw {0} and {1} in {2}s".format(strStartTime, strEndTime, round(end-start,2)))
            #At the end, get next 5 minutes of data

            if finalTimeDetla > 1: #means we still had 1,000,000 records so we had to go down to range of seconds 
                startTime=startTime + timedelta(minutes=finalTimeDetla)
            elif finalTimeDetla == 1: #means we still had 1,000,000 records so we had to go down to range of seconds 
                startTime=startTime + timedelta(seconds=secs)

        else:
            replayLogger.error("Failed to get data on {0} from: {1} to {2}".format(server, strStartTime, strEndTime))
            time.sleep(delay*12)  # maybe search failed because server is overloaded. Let is wait a bit before hitting server again with requests

if __name__ == '__main__':
    
    #read from command line
    if len(sys.argv) < 6 or len(sys.argv) > 6:
        print("Script expects an argument for server, startTime and endTime")
        print("Usage: python getArcsightEvents4.py <server> <startTime> <endTime> <seedSession>" )
    if len(sys.argv) == 5:
        server=sys.argv[1].strip()
        startTime=sys.argv[2].strip()
        endTime=sys.argv[3].strip()
        seedsession = int(sys.argv[4].strip())
        configFile = sys.argv[5].strip()       
        #print(seedsession)
        

    #read config from json formted properties file
    #configFile = "/home/vince/properties.json"
    
    with open(configFile) as json_file:
        data = json.load(json_file)
        username = data['username']
        password = data['password']
        port = data['port']
        increments = data['increments']
        delay = data['delay']
        retries = data['retries']
        initialTimedeltaMins = data['timedeltaMins']
        baseLogDir = data['baseLogDir']
        baseEventDir = data['baseEventDir']

    startTime=datetime.strptime(startTime,"%Y-%m-%dT%H:%M:%S")
    endTime=datetime.strptime(endTime,"%Y-%m-%dT%H:%M:%S")


    #customize file handers
    #create file handler for errorLogger
    FORMAT = logging.Formatter('%(asctime)-15s: %(levelname)s:  %(message)s')
    open(baseLogDir+server+'_'+str(startTime.month)+'_'+str(startTime.year)+'_Extract.log', 'a').close()
    fh = logging.FileHandler(baseLogDir+server+'_'+str(startTime.month)+'_'+str(startTime.year)+'_Extract.log')
    fh.setFormatter(FORMAT)
    logger.addHandler(fh)

    open(baseLogDir+server+'_'+str(startTime.month)+'_'+str(startTime.year)+'_Extract_errors.log', 'a').close()
    fhE = logging.FileHandler(baseLogDir+server+'_'+str(startTime.month)+'_'+str(startTime.year)+'_Extract_errors.log')
    fhE.setFormatter(FORMAT)
    errorLogger.addHandler(fhE)

    open(baseLogDir+server+'_'+str(startTime.month)+'_'+str(startTime.year)+'_missed_search_errors.log', 'a').close()
    fhR = logging.FileHandler(baseLogDir+server+'_'+str(startTime.month)+'_'+str(startTime.year)+'_missed_search_errors.log')
    fhR.setFormatter(logging.Formatter('%(message)s'))
    replayLogger.addHandler(fhE)    
    #loggers = loggers + heavyLoggers    
    
    beginDataExtraction(server,port,startTime,endTime, initialTimedeltaMins, username, password, delay, retries, baseEventDir, seedsession)
    
    """
    Had planned to use multithreading but didnt run as fast as i had originally anticipated. So i changed approach 
    trackThreads = []
    for logger in loggers:
        loggerThreadObj = threading.Thread(target=beginDataExtraction, args=[logger,port,startTime,endTime, initialTimedeltaMins, username, password, delay, retries])
        loggerThreadObj.start()
        trackThreads.append(loggerThreadObj)

    logger.info(trackThreads)
    """
