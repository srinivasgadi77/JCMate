#!/usr/bin/python
# Copyright (C) 2018 Oracle PEO
# Author: Sunil Kumar Uppara sunilkumar.u@oracle.com
#script to parse failed job logs
##

import json
import requests
import urllib
import urllib2
import HTMLParser
import sys
import os
import os.path
import commands
from requests.auth import HTTPDigestAuth

''' Verify if jobid is passed as argument '''

if len(sys.argv) != 2 :
        print("pass jobid as argument to script")
        sys.exit()

jobid = sys.argv[1]

''' Defining API LINKS and JOB ID '''

main_job_api = 'http://dis-tools.us.oracle.com/CSIJC/api/v1/jobs/'
main_api_user = 'FM_API_USER'
main_api_passwd = 'FM_TEST'
sub_job_api = 'http://dis-tools.us.oracle.com/CSIJC/api/v1/jobs/'
action_log_api = 'http://dis-tools.us.oracle.com/apex/xerxes/jobAction/jobActionLog/'
sub_job_list = []
action_list = []
f = open("/root/action_log_"+jobid+".txt", "w+")
log_file = "/root/action_fail_log_"+jobid+".txt"

if os.path.exists(log_file):
	os.remove(log_file)
else:
	f1 = open("/root/action_fail_log_"+jobid+".txt", "w+")

''' Check if JOB-ID provided is correct '''

apiurl = requests.get(main_job_api + jobid, auth=(main_api_user, main_api_passwd))
data = apiurl.json()
data1 = data['data']
if data1 == "JOBID NOT FOUND":
        print(jobid +'\t' +data1)
        sys.exit()


''' Collect data from API for Parent Job '''

def parentJobType():
        json_data = requests.get(main_job_api + jobid, auth=(main_api_user, main_api_passwd)).content
        data = json.loads(json_data)

        try:
                data1 = data['data']['action_count']
        except KeyError as error:
                data1 = 0

        if data1 == 0:
                print("For any failed jobs, refer log file " + log_file)
		#data2 = data['data']['job_id']
		#print(type(data2))
		sub_job_list_1 = SubJobList()
		failActionList(sub_job_list_1)
				
        else:
                print("For any failed jobs, refer log file " + log_file)
		#data2 = data['data']['action_id']
		#print(type(data2))
		sub_job_list = [jobid]
		failActionList(sub_job_list)
				
''' Generate sub-job list '''
def SubJobList():
	#print(type(data))
	data2 = data['data']['joblist']
	for jstatus in data2:
                sub_job_list.append(jstatus['job_id'])
	return sub_job_list
				
''' Generate Failed action list and parse log '''
def failActionList(sub_job_list):
        for substatus in sub_job_list:
                substatus1 = str(substatus)
                sub_job_json_data = requests.get(sub_job_api + substatus1, auth=(main_api_user, main_api_passwd)).content
                data = json.loads(sub_job_json_data)
                data1 = data['data']['actions']
                for jobaction in data1:
                        actionstatus = str(jobaction['action_status'])
                        if actionstatus == "FAILED" :
                                action_list = [(jobaction['action_id'])]
				#print(action_list)
				failActionLogParse(action_list)
								
								
''' Capture Failed action log along with hostname '''
def failActionLogParse(action_list):
	for failedaction in action_list:	
                failedaction1 = str(failedaction)
		#print(failedaction1)
                fail_action_log_data = requests.get(action_log_api + failedaction1).content
                f = open("/root/action_log_"+jobid+".txt", "w")
                f.write(fail_action_log_data)
                f.close()
                rel,output = commands.getstatusoutput("cat /root/action_log_'"+jobid+"'.txt | grep -i 'executed on' | cut -d ':' -f 5 >> /root/action_fail_log_'"+jobid+"'.txt")
                rel1,output1 = commands.getstatusoutput("echo '**************************************************************' >> /root/action_fail_log_'"+jobid+"'.txt")
                rel2,output2 = commands.getstatusoutput("cat /root/action_log_'"+jobid+"'.txt | egrep -i 'fail|error' >> /root/action_fail_log_'"+jobid+"'.txt")
                rel3,output3 = commands.getstatusoutput("echo '**************************************************************' >> /root/action_fail_log_'"+jobid+"'.txt")
                rel4,output4 = commands.getstatusoutput("echo '**************************************************************' >> /root/action_fail_log_'"+jobid+"'.txt")


	
	
f.close()

# Start of Main program
if __name__ == "__main__" :
        parentJobType()
