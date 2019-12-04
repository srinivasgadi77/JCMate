#!/root/python27
from threading import Thread
import shlex
from subprocess import Popen, PIPE
import os, sys
import time
import logging
import argparse
import platform
import socket

success_execution=[]
failure_execution=[]
not_reachable=[]
#chekcing whether the host is live
def check_host_alive(hosts,timeout=5):
    for host in hosts:
        try:
            socket.create_connection((host,22),timeout=timeout)
        except:
            logging.error("SKIP:>> Server %s is not reachable."%host)
            print ("SKIP:>> Server %s is not reachable."%host)
            not_reachable.append(host)

    logging.info('\n** %s/%s are down.\nWorking on %s/%s\n'%(len(not_reachable),len(hosts),len(hosts)-len(not_reachable),len(hosts)))
    return list(set(hosts)-set(not_reachable))

def execute(host,cnt):
        print "=> %s: Executing on %s\n" %(cnt,host)
        logging.info("=> %s: Executing on %s\n" %(cnt,host))

        run_cmd="/root/pass.sh %s '/usr/bin/curl -s http://pd-wls-adc-01/scripts/jc_package_installation.py | python;/usr/bin/curl -s http://pd-wls-adc-01/scripts/upgrade_cma233.sh | sh' 2>/dev/null" %host
        logging.info(run_cmd)

        #executing the command on remote server
        cmd = Popen(shlex.split(run_cmd),stdout=PIPE, stderr=PIPE)
        try:
           op,er=cmd.stdout,cmd.stderr
           result=op.read()
           success_message='Cma233 : OK|Cron : OK |packages : OK'

           if result.split('\n')[-2].strip() == success_message:
              success_execution.append(host)            
           else:
              failure_execution.append(host)
           logging.info('%s >> %s' %(host,result))

           error= er.read().strip()
           if error:
              logging.error('Not able to execute on %s\n%s' %(host,error))
        except:
           logging.exception('Failed to execute on host %s' %host)

        print "Execution completed on  %s\n" %host
        logging.info("<<=%s: Execution completed on  %s\n" %(cnt,host))

if __name__ == '__main__':

    CURRENT_TIME=time.strftime('%d%m%Y_%H%m%S')
    FILE='/tmp/jc_pkg_reinstall_%s' %CURRENT_TIME
    print "\nLog file: %s.log" %FILE
    #Logging
    logging.basicConfig(filename='%s.log' %(FILE), filemode='w', format='%(asctime)s-%(process)d-%(levelname)s-%(message)s',level=logging.DEBUG)

    logging.info('Initiated Log.')
    #verifiying the running host
    if not platform.uname()[1].split('.')[0] in  ['dlsun385','slciayu']:
        sys.exit('It can executed only from trusted host(dlsun385\slciayu)\n')

    parser = argparse.ArgumentParser(description='JC client dependent pkg re-installation')
    parser.add_argument('-clients', '--clients', nargs='*', help='Provide the clients to install pkgs')
    parser.add_argument('-f','--file', type=argparse.FileType('r'),help='Provide the list of servers in a file')
    args = parser.parse_args()

    hosts_data= ''

    if args.file:
      hosts = args.file.readlines()
      hosts_data = [ host.strip() for host in hosts ]

    if args.clients:
      hosts_data = args.clients

    if hosts_data:
      #filter removes the empty rows from file 
      live_hosts = check_host_alive(filter(None,hosts_data))
    else:
      sys.exit('\n\tPlease provide either file and hostnams\n')

    threads=[]

    for cnt,host in enumerate(live_hosts):
        t=Thread(target=execute,args=(host,cnt+1,))
        threads.append(t)
        t.start()

    for trd in threads:trd.join()

    print "All threads are completed."
    logging.info('SUCCESSFUL on %s/%s' %(len(success_execution),len(live_hosts)))
     
    #Displaying the all log files
    success_log='%s_success_hosts'%FILE
    failure_log='%s_failure_hosts'%FILE
    notreachable_log='%s_not_reachable_hosts'%FILE

    print "\n\tEXECUTION STATS AND LOG DETAILS:"
   
    total_hosts=len(filter(None,hosts_data))
    print "TOTAL SUBMITTED HOSTS: %s" %total_hosts
    print "NOT REACHABLE:%s" %(len(not_reachable))
    print "SUCCESSFULL ON %s/%s" %(len(success_execution),len(live_hosts))
    print "FAILURE ON %s/%s\n" %(len(failure_execution),len(live_hosts))

    print "\nCOMPLETE Log file: %s.log" %FILE

    with open(success_log,'w') as success:
        for host in success_execution:
          success.write(host+"\n")    
    print "SUCCESS_HOSTS:%s\n" %success_log

    if failure_execution:
        with open(failure_log,'w') as failure:
           for host in failure_execution:
              failure.write(host+"\n")
        print "FAILURES_HOSTS:%s" %failure_log

    if not_reachable:
        with open(notreachable_log,'w') as notreachable:
          for host in not_reachable:
              notreachable.write(host+"\n")
        print "NOT_REACHABLE_HOSTS:%s" %notreachable_log

      
    logging.info('-- DONE --')
