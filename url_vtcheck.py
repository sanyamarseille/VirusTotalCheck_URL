#!/usr/bin/env python
#coding:UTF-8

###############################
###     Load Modules        ###
###############################
import requests
import json
from time import sleep

###############################
###     API infomation      ###
###############################
apikey = ""
vturl = 'https://www.virustotal.com/vtapi/v2/url/report'
vturl_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
additionalinfo = True

###############################
### source & result setting ###
###############################
sourcelist = "./sourcelist.txt"
resultlist = "./resultlist.txt"

### read source URL
sourcefile = open(sourcelist,"r")
targeturl = sourcefile.readline()
### write result
resultfile = open(resultlist,"w+")

###############################
###     set var             ###
###############################
i = 0
sleeptime = 16

###############################
###     main    program     ###
###############################
while targeturl:
    if i != 0:
        sleep(sleeptime)
    params = {'apikey': apikey, 'resource': targeturl, 'allinfo': additionalinfo}
    response = requests.get(vturl, params=params).json()
    if response['response_code'] == 0:
        sleep(sleeptime)
        params = {'apikey': apikey, 'url': targeturl}
        response = requests.post(vturl_scan, params).json()
        sleep(sleeptime)
        params = {'apikey': apikey, 'resource': response['scan_id'], 'allinfo': additionalinfo}
        response = requests.get(vturl, params=params).json()
    resultfile.write(str(response) + "\n")
    targeturl = sourcefile.readline()
    i += 1

sourcefile.close()
resultfile.close()
print "check : " + str(i) + " URLs"