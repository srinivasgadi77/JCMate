#!/usr/local/python3/bin/python3.6
# # -*- coding: utf-8 -*-
# from __future__ import unicode_literals
import argparse
import os
import time
import threading
import subprocess
import urllib.request
import sys
import platform
import getpass
import paramiko
import shutil
import multiprocessing as mp
import re

locker=threading.Lock()
disk_space_issues = []
Hosts_down = []
Solaris_hosts = []
NotWorkedWithStandardPasswd=[]
Non_prod_hosts = []
Prod_hosts = []
Non_linux_sol=[]
Invalid_hosts = []
Host_fqdn = []
Identity_mismatch = []
Archs_not_supported = []
Not_supported_os = []
Misc_issues = []
os_number_type = {}
host_regions = []
Rpm_package_issues = []
Fix_identity_failed = []
PassWordChangeData = []
PassWordNotChanged = []
HostInfo = []
AuthFailed = []
UserManaged = []
NoSudoAccess = []
Success = []
Low_disk_space = []
Behind_firewall = []
CMA_failures = []

CURRENT_TIME=time.strftime('%d%m%Y_%H%m%S')

def check_host_alive(host):
    import subprocess
    """Use the ping utility to attempt to reach the host. We send 3 packets
    ('-c 3') and wait 3 milliseconds ('-W 3') for a response. The function
    returns the return code from the ping utility.
    if it returns other than 0, means that host might down
    """
    return_code = subprocess.call(['ping', '-w','5','-c', '5', host],
                           stdout=open(os.devnull, 'w'),
                           stderr=open(os.devnull, 'w'))
    with locker:
       return return_code

def whichOs(host):
    ''' Its tell which type of host , wther it's a Linux and Solaries'''
    try:
      res,err = execute_command_at_remote(host,'uname')

      if err:
         which_os=err.strip()
      else:
         which_os=res.strip()
    except Exception as e:
      which_os = str(e)

    with locker:
        return which_os

def groupByImage(host,state):
    env=whichOs(host)
    if env.strip() in ['Linux','SunOS']:
        if env == 'SunOS':
            # Solaris_hosts.append('%s > %s' %(host,env))
            writeToFile('Solaris_hosts', [f'{host} > {env}'])
            state = False
    else:
        # Misc_issues.append('%s > %s' %(host, env))
        writeToFile('Misc_issues', [f'{host} > {env}'])
        state = False
    return state

def user_managed(host,state):
    '''Try to login with root user and check whther its able to login if not check the SLM status in DevOps portal , its its usermanaged its confirm the status.'''
    cmd="/tmp/pass.sh %s uptime %s 2>/dev/null" %(host,root_password)
    #result=os.popen('timeout 3 ssh -o PasswordAuthentication=no -o PreferredAuthentications=publickey -o StrictHostKeyChecking=no -o ConnectTimeout=3 %s uptime' %host).read()
    result = os.popen(cmd).read().strip()
    if result and 'average' in result:
        state=False
    else:
        host = host.split('.')[0]
        cmd  = "/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/%s/data | grep -i slm_exclusion" %host
        slm_tag=os.popen(cmd).read().strip()
        if 'User' in slm_tag:
            UserManaged.append('%s > %s '%(host,slm_tag))
        else:
            NotWorkedWithStandardPasswd.append('%s > %s '%(host,slm_tag))
        state=True

    with locker:
       return state
def getUserManagedHosts(host,state):
    print(f' => {host} in usermanaged')
    # This method will verify the SLM tag in DevOps portal whether this server already marked as User Managed
    host = host.split('.')[0]
    cmd  = "/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/%s/data | grep -i slm_exclusion" %host
    try:
        p1 = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
        result,error = p1.communicate()
        slm_tag = str(result, 'utf-8').strip() if result else result
        error = str(error,  'utf-8').strip() if error else error

        if 'User' in  slm_tag or 'Password' in slm_tag:#
            writeToFile('UserManaged', [f'{host} > {slm_tag}'])
            state=True
        else:
            state=False
    except Exception as e:
        writeToFile('Misc_issues', [f'{host} > {str(e)}'])
        state=True

    return state
def get_host_region(host,state):
    host_region=''
    try:
        host_API = 'http://devops.oraclecorp.com/ws/public/v1/hosts/assets/%s/properties/' %(host.split('.')[0])
        response = urllib.request.urlopen(host_API).read()
        response = str(response,'utf-8')
        for region in response.split(","):
            try:
                if region.split(":")[0] == ' "eng-region"' :
                    host_region = (region.split(":")[1].replace('"','')).strip()
            except Exception as e:
                Misc_issues.append('%s > %s : get_host_region_in' %(host,str(e)))
                host_region = False

    except Exception as e:
        Misc_issues.append('%s > %s : get_host_region ' %(host,str(e)))
        host_region = False
    return host_region

def groupByRegion(host,state):
    region= get_host_region(host,state)
    if region:
        # host_regions.append('%s > %s' %(host,region))
        writeToFile('host_regions', [f'{host} > {region}'])
        state = True
    else:
        writeToFile('Invalid_hosts', [host])
        # Invalid_hosts.append(host)
        state = False
    return state

def host_env(host):
    host_location = ''
    env_type = "/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/slc13qqg/data | grep service_area|awk -F'=' '{print $2}'"
    if env_type:
        return  host_location
    else:
        return 'Invalid'

def groupByEnv(host):
    host_environ = host_env(host)
    if host_environ  == 'Invalid':
        Invalid_hosts.append(host)
        return
    elif 'Production' in host_environ:
        Prod_hosts.append(host)
        return
    else:
        Non_prod_hosts.append(host)
        return

def get_fqdn(host,state=True):
    if '.' in host:
        host=host.split('.')[0]
    get_data="/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/%s/data | grep  '^fqdn=' | awk -F '=' '{print $2}'" %host
    #full_name=os.popen(get_data).read().strip()
    full_name,error=execute_command_at_local(get_data)
    if full_name:
       writeToFile('Host_fqdn',[full_name])
       return full_name
    else:
       writeToFile('Invalid_hosts',[f'{host} > {error}'])

def getAllData(host,state):
    cmd="/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/%s/data | egrep -i '^fqdn|user_email|use=|slm_exclusion'" %(host.split('.')[0])
    result = os.popen(cmd).read().strip()
    if result:
        x={}
        try:
            for i in result.split('\n'):
                x[i.split('=')[0]] = i.split('=')[1]
            writeToFile('HostInfo', [f"{x['fqdn']}|{x['user_email']}|{x['use']}|{x['slm_exclusion']}"])
        except Exception as e:
            writeToFile('Misc_issues',[f'{host} > {str(e)}'])
    else:
        writeToFile('Invalid_hosts',[f'{host} > "Does not exists in DevOps."'])

def os_number(host,state):
    ''' its return the which version of OS'''
    import re
    try:
       res,err = execute_command_at_remote(host,'cat /etc/redhat-release')
       #FIXIT: Need to know if all VMs are supported or any restrictions
       if 'VM' in res :
         os_ver='VM'
         pass

       else:
          os_ver=eval(re.search(r'\d',res).group())
          if os_ver < 5:
              Not_supported_os.append('%s > %s' %(host,res.strip()))
              state,os_ver = False,os_ver

    except Exception as e:
        Misc_issues.append('%s > %s' %(host,str(e)))
        state,os_ver = False,''

    return (state,os_ver)

def get_identity(host,state):
    ''' chekc the below 'cmd_if_exists' exists and if not cmd_identity its a hostname mismatch for outside and inside
    if below both paths does not exists , its RPM packages issues.'''

    cmd_if_exists = 'ls /usr/local/pdit/tools/pdit-mc-srv/etc/mcollective/server_v28.cfg &>/dev/null; echo $?'
    cmd_identity = 'grep -w "identity" /usr/local/pdit/tools/pdit-mc-srv/etc/mcollective/server_v28.cfg &>/dev/null; echo $?'

    res_host,err_host = execute_command_at_remote(host,'hostname')
    try:
        if res_host.strip().split('.')[0] != host.split('.')[0]:
            Identity_mismatch.append('%s  >  %s' %(host,res_host.strip()))
            return False

        res_e,err_e = execute_command_at_remote(host,cmd_if_exists)
        if eval(res_e.strip()) == 0:
            res_e,err_e = execute_command_at_remote(host,cmd_identity)

            if not eval(res.strip()) == 0:
                Identity_mismatch.append(host)
                state=False
        else:
            Rpm_package_issues.append(host)
            state=False
    except Exception as e:
        state=False
        Invalid_hosts.append(host)
    return state

def execute_command_at_remote(host,command):
      ''' Execute the command on give host and return the results '''
      p = subprocess.Popen(['ssh','-q',host,command],stdout=subprocess.PIPE)
      res,err = p.communicate()
      res = str(res, 'utf-8').strip() if res else res
      err = str(res, 'utf-8').strip() if err else err
      return (res,err)


def execute_command_at_local(command):
      ''' Execute the command on give host and return the results '''
      p = subprocess.Popen([command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
      p.wait()
      res,err = p.communicate()
      res = str(res, 'utf-8').strip() if res else res
      err = str(res, 'utf-8').strip() if err else err
      return (res,err)

def fix_dentity(actualHost,state):
    ''' update the config files with actual host FQDN, its comparares the actual FQDN with DevOps portal, and update the client accordingly.'''
    host = actualHost.strip().split('.')[0]

    res,err =  execute_command_at_remote(host,'hostname -f')
    resolvHost = res.strip().split('.')[0]
    if resolvHost == host.split('.')[0]:
        return

    _,os_ver = os_number(host,state)
    if os_ver == 'VM':
        print('>> VM: Ignore %s' %host)
        return

    if os_ver in [ 5,6 ]:
      hostname_update="hostname %s;sed -i '/HOSTNAME/d' /etc/sysconfig/network;echo 'HOSTNAME=%s' >>/etc/sysconfig/network;hostname;hostname -f" %(host,host)

      res,err = execute_command_at_remote(host,hostname_update)
      hostIP = os.popen('host %s' %host).read().strip().split()[-1]
      updatedHostShortName,updateHostFullName = res.split()


      if updatedHostShortName.strip() != host or updateHostFullName.strip().split('.')[0] != host :
         print('Fixing Fullname')
         hostfullName = get_fqdn(host)

         fix_etc_hosts_file = "sed -i '/%s/d' /etc/hosts;echo '%s %s %s' >> /etc/hosts" %(hostIP,hostIP,hostfullName,host)
         res,err =  execute_command_at_remote(host,fix_etc_hosts_file)

         if res.strip():
            Fix_identity_failed.append('%s > %s' %(host,err.strip()))
         else:
            print('Identity fixed on %s' %host)

    elif os_ver == 7:
        setHostname = "hostname %s;echo '%s' > /etc/hostname" %(host,host)
        res,err =  execute_command_at_remote(host,setHostname)

        if res.strip():
            Fix_identity_failed.append('%s > %s' %(host,err.strip()))

def get_archs(host,state):
    ''' get the arch type'''
    pkgs_supported_archs = ('x86_64','i386','i686')
    try:
        #p = subprocess.Popen(['ssh','-q',host,'uname -i'],stdout=subprocess.PIPE)
        res,err = execute_command_at_remote(host,'uname -i')
        #res,err = p.communicate()
        arch = res.strip()

        if not arch in pkgs_supported_archs:
           Archs_not_supported.append("%s > %s" %(host,res.strip()))
           state = False
    except Exception as e:
         Misc_issues.append("%s > %s" %(host,str(e)))
         state = False
    return state

def disk_space(host,state):
    ''' Check the root file system space and retuen if the space below 95%'''
    try:
        cmd_disk = "df -HP / | awk '{print $5}' | tail -1"
        res,err = execute_command_at_remote(host,cmd_disk)
        disk_vol =eval(res.split('%')[0])

        if disk_vol > 95:
           disk_space_issues.append("%s > %s" %(host,disk_vol))
           state = False

    except Exception as e:
         Misc_issues.append("%s > %s" %(host,str(e)))
         state = False
    return state

def default_fucns(target_fun,host,default):
    state = True
    if default:
        lv = check_host_alive(host)
        if lv:
            # Hosts_down.append(host)
            writeToFile('Hosts_down',[host])
            return

        um = getUserManagedHosts(host,state)
        if um:
            return
    target_fun(host,state)

def scanner(host,state):
      #Checking OS env
      if not groupByImage(host,state):
          return

      #Chekcing the hos  region
      if not get_host_region(host,state):
         Invalid_hosts.append(host)
         return

      if not os_number(host,state)[0]:
         return

      if not get_archs(host,state):
         return

      if not disk_space(host,state):
          return

      if not get_identity(host,state):
          return

      groupByEnv(host)
      return

#=============
def executeWithkeys(host, username, SSHKey, command, isFile, results):


    # Initialize the remote conection
    ssh = paramiko.SSHClient()
    command_exe = command
    source_folder = os.path.dirname(command)
    file1 = os.path.basename(command)
    localpath = '/tmp'

    state = False
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, key_filename=SSHKey,timeout=30)
        try:
            print('LogIN Success')
            os_type_in, os_type_out, os_type_err = ssh.exec_command('uname')
            os_type_out = str(os_type_out.read(), 'utf-8').strip()
            os_type_err = str(os_type_err.read(), 'utf-8').strip()

            if os_type_out in ['Darwin', 'VMkernel']:
                writeToFile('NonLinuxHost', [f'{host} > {os_type_out} > IGNORE'])
                return True

            if os_type_err and not 'chdir' in os_type_err:
                writeToFile('Misc_issues', [f'{host} > {os_type_err} > OSERROR'])
                return True

            if isFile:
                '''get the FUll path of file to execute'''
                command_exe = os.path.join(localpath, file1)
                ssh.exec_command(f'chmod +x {command_exe}')

                '''Get the file type whether its a python/Shell based the file shebang, since there are few other linux flavours HP , file must be executed with type.'''
                shegang_in, shegang_out, shegang_err = ssh.exec_command(f" head -1 {command_exe}")

                ''' Converting the resulted bytes to string'''
                dataout = str(shegang_out.read(), 'utf-8').strip()
                dataerr = str(shegang_err.read(), 'utf-8').strip()

                # print(f'dataerr1 => {dataerr}')

                if dataout.startswith('#!'):
                    FileType = dataout[2:]
                    if os.path.basename(command_exe) == 'jc_package_installation.py':
                        command_exe = f'{FileType} {command_exe} {host}'
                    else:
                        command_exe = f'{FileType} {command_exe}'

            given_cmd_stdin, given_cmd_out, given_cmd_stderr = ssh.exec_command(f"{command_exe}")
            # print(f' ==>given_cmd_out = {given_cmd_stdin.read()}, given_cmd_stderr.read() = {given_cmd_stderr}\n')

            dataout = str(given_cmd_out.read(), 'utf-8').strip()
            dataerr = str(given_cmd_stderr.read(), 'utf-8').strip()

            # print(f'dataout => {dataout}')
            # print(f'dataerr2 => {dataerr}')

            '''Slice the last 4 lines and remove any whitepsace and capture last two lines to get the accurate status '''
            short_res = list(map(lambda line: line.strip(), dataout.split('\n')))
            short_err = list(map(lambda line: line.strip(), dataerr.split('\n')))
            # short_res=dataout.split('\n')
            # short_err=dataerr.split('\n')

            '''Converting the res from list to str '''

            if ('incident' in dataerr or 'sorry' in dataerr) and not dataout:
                writeToFile('NoSudoAccess', [f'{host} > {short_err}'])
                state = True
            elif 'Low_disk_space' in dataout:
                writeToFile('Low_disk_space', [f'{host} > {short_res}'])
                state = True
            elif 'firewall' in dataout:
                writeToFile('Behind_firewall', [f'{host} > {short_res}'])
                state = True
            elif 'ERROR:CMA Checks failed' in dataout:
                writeToFile('CMA_failures', [f'{host} > {short_res}'])
                state = True
            else:
                match_state = 0
                if REGEX_ITEM != 'None':
                    for res in short_res:
                        if REGEX_ITEM == 'in':
                            if REGEX_VALUE in res:
                                writeToFile('Success', [f'{host} > {res}'])
                                match_state += 1
                            # else:
                            #     writeToFile('NoMatch', [f'{host} > '])
                        elif eval(f'res.{REGEX_ITEM}("{REGEX_VALUE}")'):
                            writeToFile('Success', [f'{host} > {res}'])
                            match_state += 1
                        # else:
                    if not match_state:
                        writeToFile('NoMatch', [f'{host} > '])
                    state = True
                else:
                    '''Converting the res from list to str '''
                    try:
                        # short_res=short_res[0]
                        short_res = ' '.join(short_res[-last_tripped_lines:])
                        writeToFile('Success', [f'{host} > {short_res}'])
                    except Exception as e:
                        writeToFile('ERROR', [f'{host} > {str(e)}'])
                    state = True

        except Exception  as e:
            results.append('%s > %s : Internal error' % (host, str(e)))
            state = False

    except Exception as e:
        print('key ERROR : %s > %s' % (host, str(e)))
        results.append('%s > %s' % (host, str(e)))
        state = False
    ssh.close()
    return state


#=============

def executeWithPasswd(host,username,passwd,command,isFile,results):
    #Initialize the remote conection
    ssh = paramiko.SSHClient()
    command_exe=command
    source_folder=os.path.dirname(command)
    file1=os.path.basename(command)
    localpath='/tmp'

    state=False
    try:
         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
         ssh.connect(host, username=username, password=passwd,timeout=30)
         try:
            print('LogIN Success')
            os_type_in, os_type_out, os_type_err = ssh.exec_command('uname')
            os_type_out = str(os_type_out.read(), 'utf-8').strip()
            os_type_err = str(os_type_err.read(), 'utf-8').strip()

            if os_type_out in ['Darwin','VMkernel']:
                writeToFile('NonLinuxHost', [f'{host} > {os_type_out} > IGNORE'])
                return True

            if os_type_err and not 'chdir' in os_type_err:
                writeToFile('Misc_issues', [f'{host} > OSERROR'])
                return True

            if isFile:
                # print('Its file')
                ftp_client=ssh.open_sftp()
                '''if its file scp the remote host to local host'''
                ftp_client.put(os.path.join(source_folder,file1),os.path.join(localpath,file1))
                ftp_client.close()

                '''get the FUll path of file to execute'''
                command_exe=os.path.join(localpath,file1)
                ssh.exec_command(f'chmod +x {command_exe}')

                '''Get the file type whether its a python/Shell based the file shebang, since there are few other linux flavours HP , file must be executed with type.'''
                shegang_in, shegang_out, shegang_err = ssh.exec_command(f" head -1 {command_exe}")

                ''' Converting the resulted bytes to string'''
                dataout = str(shegang_out.read(), 'utf-8').strip()
                dataerr = str(shegang_err.read(), 'utf-8').strip()

                # print(f'dataerr1 => {dataerr}')

                if dataout.startswith('#!'):
                    FileType = dataout[2:]
                    if os.path.basename(command_exe) == 'jc_package_installation.py':
                        command_exe = f'{FileType} {command_exe} {host}'
                    else:
                        command_exe=f'{FileType} {command_exe}'
            ''' Executing the provided command/file with sudo'''
            if username in ['root','']:
                given_cmd_stdin, given_cmd_out, given_cmd_stderr = ssh.exec_command(f"{command_exe}")
                #print(f' ==>given_cmd_out = {given_cmd_stdin.read()}, given_cmd_stderr.read() = {given_cmd_stderr}\n')

                try:
                    ######## START : COPY SOURCE KEYS TO LOCAL HOST ######
                    ''' download pub keys to enable password less authentication from trusted host'''
                    SOURCE_FOLDER = '/root/.ssh'
                    PUB_KEY = 'id_rsa.pub'
                    LOCALPATH = '/tmp'

                    #Sometimes, pubkey does not exists on host key, in that case just ignore keycopy method and move on.

                    proc  = subprocess.Popen([f'ls -rtl {os.path.join(SOURCE_FOLDER, PUB_KEY)} &>/dev/null;echo $?'],stdout=subprocess.PIPE, shell=True)

                    KEY_PATH_EXISTS,error = proc.communicate()

                    KEY_PATH_EXISTS=str(KEY_PATH_EXISTS, 'utf-8').strip()

                    if not KEY_PATH_EXISTS == str(0):
                        print(f'WARNING: {os.path.join(SOURCE_FOLDER, PUB_KEY)} Does not exists hence skipping the keycopy method')
                    else:
                        '''Download key from source to local'''
                        ftp_client = ssh.open_sftp()
                        ftp_client.put(os.path.join(SOURCE_FOLDER, PUB_KEY), os.path.join(LOCALPATH, PUB_KEY))
                        ftp_client.close()

                        LOCAL_TEMP_KEY_PATH = os.path.join(LOCALPATH, PUB_KEY)

                        '''Keys storage path is differ from SunOS OS type to other OSs,
                            if its SunOS --> /.ssh
                            else its is /root/.ssh'''
                        HOMEDIR = '/' if os_type_out in  ['SunOS','AIX', 'HP-UX'] else '/root/'

                        DEST_KEY_FOLDER=f'{HOMEDIR}.ssh'
                        DEST_KEY_FILE = 'authorized_keys'

                        with open(os.path.join(SOURCE_FOLDER, PUB_KEY), 'r') as line:
                            SOURCE_KEY_IDENTITY = line.readlines()[0].split('@')[1].strip()

                        '''creaing .ssh folder under root dir if not already exists.'''
                        ssh.exec_command(f" mkdir {DEST_KEY_FOLDER} ")


                        '''Checking source host key already added to local if yes , do not copy again'''
                        KEY_CHECK_IN_LOCAL_CMD=f'grep -i {SOURCE_KEY_IDENTITY} {HOMEDIR}.ssh/authorized_keys >/dev/null 2>/dev/null;echo $?'

                        KEY_IN, KEY_OUT, KEY_ERR = ssh.exec_command(f"{KEY_CHECK_IN_LOCAL_CMD}")
                        KEY_OUT = str(KEY_OUT.read(), 'utf-8').strip()
                        KEY_ERR = str(KEY_ERR.read(), 'utf-8').strip()

                        #if os_type_out == 'SunOS' or int(KEY_OUT):
                        if int(KEY_OUT):
                            ''' appending the source pubkeys to authorized_keys in local host'''
                            KEY_ERR=''
                            stdin, stdout, stderr = ssh.exec_command(f'cat {LOCAL_TEMP_KEY_PATH}>> {os.path.join(DEST_KEY_FOLDER, DEST_KEY_FILE)};rm -rf {LOCAL_TEMP_KEY_PATH}')

                            stdout = str(stdout.read(), 'utf-8').strip()
                            KEY_ERR = str(stderr.read(), 'utf-8').strip()

                        if KEY_ERR:
                                writeToFile('Misc_issues', [f'{host} > KEY ERROR {KEY_ERR}'])

                except Exception as e:
                    writeToFile('Misc_issues', [f'{host} > {str(e)}'])
                ######## END : COPY SOURCE KEYS TO LOCAL HOST ######
            else:
                #FIXIT:Need to find a way to copy keys with sudo.
                given_cmd_stdin, given_cmd_out, given_cmd_stderr= ssh.exec_command(f"echo {passwd} |sudo -S {command_exe}")
            dataout = str(given_cmd_out.read(),'utf-8').strip()
            dataerr = str(given_cmd_stderr.read(),'utf-8').strip()

            # print(f'dataout => {dataout}')
            # print(f'dataerr2 => {dataerr}')

            '''Slice the last 4 lines and remove any whitepsace and capture last two lines to get the accurate status '''
            short_res=list(map(lambda line:line.strip(),dataout.split('\n')))
            short_err=list(map(lambda line:line.strip(),dataerr.split('\n')))
            #short_res=dataout.split('\n')
            #short_err=dataerr.split('\n')
            '''Converting the res from list to str '''
            #try:
            #    '''Stripping the lines to given number if not it print last 3 lines'''
            #    short_res = ' '.join(short_res[-int(last_tripped_lines):])
            #except Exception as e:
            #    print(f'StripError:  {e}')

            if ('incident' in dataerr or 'sorry' in dataerr ) and not dataout:
               writeToFile('NoSudoAccess', [f'{host} > {short_err}'])
               state=True
            elif 'Low_disk_space' in dataout:
               writeToFile('Low_disk_space', [f'{host} > {short_res}'])
               state=True
            elif 'firewall' in dataout:
               writeToFile('Behind_firewall', [f'{host} > {short_res}'])
               state=True
            elif 'ERROR:CMA Checks failed' in dataout:
               writeToFile('CMA_failures', [f'{host} > {short_res}'])
               state=True
            else:
#               print(f'=> regex_item %s : {REGEX_ITEM}')
#               print(f'=> regex_value %s : {REGEX_VALUE}')

               match_state = 0
               if REGEX_ITEM != 'None':
                   for res in short_res:
                       if REGEX_ITEM == 'in':
                           if REGEX_VALUE in res:
                               writeToFile('Success', [f'{host} > {res}'])
                               match_state+=1
                           # else:
                           #     writeToFile('NoMatch', [f'{host} > '])
                       elif eval(f'res.{REGEX_ITEM}("{REGEX_VALUE}")'):
                                writeToFile('Success', [f'{host} > {res}'])
                                match_state += 1
                           # else:
                   if  not match_state:
                        writeToFile('NoMatch', [f'{host} > '])
                   state = True
               else:
                  '''Converting the res from list to str '''
                  try:
                      #short_res=short_res[0]
                      short_res = ' '.join(short_res[-last_tripped_lines:])
                      writeToFile('Success', [f'{host} > {short_res}'])
                  except Exception as e:
                      writeToFile('ERROR', [f'{host} > {str(e)}'])
                  state = True

         except Exception  as e:
             results.append('%s > %s : Internal error' %(host,str(e)))
             state=False

    except Exception as e:
             results.append('%s > %s' %(host,str(e)))
             state=False
    ssh.close()
    return state

def manual_execution_old(host, username, passwords, command, isFile):
    results = []
    state = executeWithkeys(host, 'root', '/root/.ssh/id_rsa', command, isFile, results)

    '''if it worked with keys, the state must be True and it out from further attempts'''
    if state:
        print(f'==> KYE AUTHENTICATION SUCCESS')
        return
        # break

def manual_execution(host,username,passwords,command,isFile):
    # print(f'ALL password = {passwords}')
    state=True
    results = []
    '''checking whether the host is up'''
    isHostUp = check_host_alive(host)
    if isHostUp:
        writeToFile('Hosts_down',[host])
        return

    '''Key based Authentication loop'''
    keys = ['/root/.ssh/id_rsa',
 '/root/.ssh/id_rsa_adc01lgu',
 '/root/.ssh/id_rsa_pdit-dis-engsys-adm1',
 '/root/.ssh/id_rsa_slciayu',
 '/root/.ssh/id_rsa_ucl']

    for key in keys:
        # print(f'password = {password}')
        results = []
        # print(f'Key = {key}')
        #if len(passwords) == cnt and len(passwords) >1:
        state=executeWithkeys(host,'root',key,command,isFile,results)

        '''if it worked with keys, the state must be True and it out from further attempts'''
        if state:
            # print(f'==> KYE AUTHENTICATION SUCCESS')
            return
            # break

    '''Passwd based Authentication enabled'''
    for password in passwords:
        # print(f'password = {password}')
        results = []
        #if len(passwords) == cnt and len(passwords) >1:
        if passwords[-1] == password:
           results = []
           state=executeWithPasswd(host,username,password,command,isFile,results)
        else:
           results = []
           state=executeWithPasswd(host,'root',password,command,isFile,results)

        '''if it worked with keys, the state must be True and it out from further attempts'''
        if state:
            break

    if not state:
        AuthFailed.extend(results)
        writeToFile('AuthFailed',results)
    return

def terminate_on_time(processes,time_out):
    print('\n\tFetching the results , please be on hold.\n')
    while len(mp.active_children()):
        print(f'Pending tasks: {len(mp.active_children())}/{len(processes)}')
        time.sleep(3)
        for process,start_time in processes.items():
            if time.time() - start_time >  time_out:
                try:
                  if process.is_alive:
                     process.terminate()
                     time.sleep(0.2)
                     # writeToFile('TimeOut',[process.name])
                     print(f'{process.name} --> TimeOut > Terminated. \n')

                     '''-15 singnal meaning to force terminate when it runs out of given time'''
                     # if process.exitcode == -15:
                        # writeToFile('Success', [f'{process.name} > TimeOut'])
                except Exception as e:
                    print(f'Error as {str(e)}')

def writeToFile(FileName,data):
    # import pdb
    # pdb.set_trace()
    print(f'I am in writeToFile')
    print(f'FileName = {FileName}\n data = {data}')
    print(f'data type= {type(data)}')
    time.sleep(0.3)
    #print('==>Im in writeToFile\n')
    #print(f'==>File Name : {FileName}\n data : {data}')
    #print('==============\n')

    '''TagName for consolidated report'''
    TagName=FileName

    #FileName='%s_%s.log' %(FileName,CURRENT_TIME)
#    with open('%s' %FileName,'a') as hosts:
#      for host in data:
#        hosts.write(f'{host}\n')


        # if illigar_pat.search(data):
    #         print('step 3')
    #         print(f'==> BEFORE: data = {data}')
    #         data = data.replace("\\/", "/").encode().decode('unicode_escape')
    #         print(f'==> AFTER: data = {data}')
    # except exception as e:
    #     print(f'ERROR : {str(e)}')

    ''' Ignore Misc issues added to Consolidated_data file'''
    if not FileName == 'Misc_issues_%s.log'%CURRENT_TIME:
        with open(LOGFILE,'a') as consol,open('%s_final' %LOGFILE,'a') as final:
            # if FileName.startswith('Success'):
            #     FileName='Success'

            for pattern in data:
                host_data = pattern.replace('>','Sri',1).split('Sri')
                if len(host_data) > 1:
                    host, cause = host_data
                    if cause.strip() == 'TimeOut' :
                        state = cause
                        cause = ''
                    else:
                        state = TagName
                else:
                    host = pattern
                    state = TagName
                    cause = ''
                    #=========
                try:
                    re1 = re.compile(r"[<>/{}[\]~`]");
                    if re1.search(cause):
                        cause = [cause]
                except Exception as e:
                    print(f'==> ERROR while detecting illegar character : {str(e)}')
                #==========
                consol.write('%s | %s | %s\n' % (state, host, cause))
                final.write('%s | %s | %s\n' % (state, host, cause))

    else:pass
    return

def get_number_of_lines(FileName):
    return sum(1 for line in open(FileName))

def FIXIT_WriteToCsv(FileName,Consolidated_data):
    CURRENT_TIME=time.strftime('%d%m%Y_%H%m%S')
    FileName='%s_%s.csv' %(FileName,CURRENT_TIME)

    import csv
    with open(FileName, 'w') as csvfile:
        fieldnames = ['HOSTNAME', 'STATE']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in Consolidated_data:
           try:
              host,state=row.split('>')
           except:
              host=row;state=''
           writer.writerow({'HOSTNAME':host,'STATE':state})

def main():
    #CURRENT_TIME=time.strftime('%d%m%Y_%H%m%S')
    global LOGFILE, REGEX_ITEM, REGEX_VALUE
    logfile = f'/tmp/Consolidated_data_{CURRENT_TIME}.csv'

    parser = argparse.ArgumentParser(description='JC client dependent pkg installation')
    parser.add_argument('-clients', '--clients', nargs='*', help='Provide the clients to install pkgs')
    parser.add_argument('-f','--file', type=argparse.FileType('r'),help='Provide the list of servers in a file')
    parser.add_argument('--scan', action="store_true", help ='Check all possibilities of JC checks')
    parser.add_argument('--env', action="store_true", help ='get the host env whether its prod or non prod')
    parser.add_argument('--host_fqdn', action="store_true", help ='get host fqdn')
    parser.add_argument('--os_version', action="store_true", help ='get host os version')
    parser.add_argument('--identity', action="store_true", help ='finds out if there is any identity mismatch')
    parser.add_argument('--archs', action="store_true", help ='Find whether archs supports')
    parser.add_argument('--image', action="store_true", help ='Find which OS type')
    parser.add_argument('--region', action="store_true", help ='Get the host region')
    parser.add_argument('--disk', action="store_true", help ='Get the Disk vol ')
    parser.add_argument('--fixidentity', action="store_true", help ='Fix identity ')
    parser.add_argument('--usermanaged', action="store_true", help ='Check if a server able to login with either standardKeys or Standard Password ')
    parser.add_argument('--hostinfo', action="store_true", help ='Get fqdn,user_email,use,slm_exclusion')
    parser.add_argument('--manualexecute', action="store_true", help ='Login with password and execute the command on all togather ')
    parser.add_argument('--enable_passwords', action="store_true", help ='It will enable the older root passwords (inbuilt) login and execute.')
    parser.add_argument('--include_passwds', nargs='+', help = 'provide the multiple passwords with comma deliminator Ex: --enable_passwords --include_passwds "passwd1,passwd2, ...,passwdn"')
    parser.add_argument('--cmd', action="store", help ='pass the command to execute')
    parser.add_argument('--timeout', default=300, help ='wait timeout seconds to kill the process, default its 300s.')
    parser.add_argument('--skip_passwd', action="store_true", help ='bypass the prompting user password')
    parser.add_argument('--parse_passwd', help ='Parse the user password to assit with SUDO login.')
    parser.add_argument('--logfile', default=logfile, help ='You can pass log file as your choice else default logfile will be generated. ')
    parser.add_argument('--last_lines', default=1, help ='By default, it print last 2 lines of O/P,can be modified by addition number')
    parser.add_argument('--regex_item', action="store", help='Indicate the regex what to filter')
    parser.add_argument('--regex_value', action="store", help='regex value to filter')

    args = parser.parse_args()
    hosts_data= ''

    TIMEOUT=int(args.timeout)
    REGEX_ITEM = args.regex_item
    REGEX_VALUE = args.regex_value

    LOGFILE = args.logfile
    print('LogFile:',LOGFILE)

    if args.last_lines:
        global last_tripped_lines
        last_tripped_lines = int(args.last_lines)

    # temp file, will be removed end of this script
    with open(f'{LOGFILE}_monitor','w') as tmp:pass

    #Erasing the logfile if its already created
    with open(LOGFILE,'w') as log:pass

    if args.file:
      hosts = args.file.readlines()
      #Exclude console hosts if there are any
      hosts_data = set([ host.strip() for host in hosts if not '-c.' in host])

    if args.clients:
      hosts_data = args.clients

    def thread_init(target,default=True):
        start_time=time.time()
        threads_l = []
        process_data = {}
        total_hosts=len(set(filter(None,hosts_data)))

        if target.__name__ == 'manual_execution':
            command = args.cmd
            cwd=os.getcwd()
            FullFilePath=os.path.join(cwd,command)
            isFile=False

            #Check whether provided command is linux command or file
            if os.path.exists(FullFilePath):
                command=FullFilePath
                isFile=True
            elif shutil.which(command):
                command = command
            else:
                FIXIT:sys.exit(f'\tERROR: {command} does exists.\n')
                pass

            username=os.popen('logname').read().split()[0]

            '''include_passwds should accept the password with either comma or space '''
            passwords=['']
            if args.include_passwds:
                if not args.enable_passwords:
                    file_name=os.path.basename(__file__)
                    sys.exit(f'\t--enable_passwords tag mandatory with --include_passwds\n\tUSAGE:{file_name} --file <FILENAME> --manualexecute --enable_passwords --include_passwds passwd1,passwd2...passwdN --cmd <COMMAND/FILE>')

            if args.enable_passwords:
                '''Inbild older passwords'''
                passwords = ['HuNAb_Ku', '$hArk13$', 'welcome1', 'S41v1@n3', 'L0ck!tup', 'welecome123', '0pnW0r1d', 'D1s@P3&0', 'welcome', 'L@n_B$cK7', '$t33L3R$', '$h@rk13$', 'Ca8ra_Ka','r00t06','L@n_B$cK7','Sy7vi@n$_p','K@z^h1r0']

                if args.include_passwds:
                    passwd = args.include_passwds
                    if len(passwd) == 1 and ',' in passwd[0]:
                        passwd = passwd[0].split(',')

                    ''' Add external prov'''
                    passwords.extend(passwd)

                '''remove duplicate password entries '''
                passwords=list(set(passwords))

                ''' which will insert empty element at beginning of the list to check for the Key based Authentication and current prod and dev passwords respectively '''
                passwords.insert(0, '')
                passwords.insert(1, 'I$@Be1L$_M')
                passwords.insert(2, 'S$1v!@nE_p')
            else:
                username = input('\nLogin as : ')

            ''' append the user password to list of password to try as final option'''
            if args.skip_passwd:
                passwd=''
            if not args.parse_passwd == 'None':
                passwd = args.parse_passwd
                #passwd  = getpass.getpass(f"\n{username}@password: ")
            else:
                passwd = False

            if passwd:
                passwords.append(passwd)
            else:
                print(f'No password, Hence skiping {username}\'s login.\n')
                username='root'
                time.sleep(1)
            print(f'\n\t--> "{command}" will be executed across and get the status.')
            time.sleep(1)

            for sno,host in enumerate(set(filter(None,hosts_data))):
                print('>%s/%s. Checking on %s' %(sno+1,total_hosts,host))
                p=mp.Process(target=manual_execution, args=(host,username,passwords,command,isFile))
                p.name=host
                process_data[p] = time.time()
                p.start()
            terminate_on_time(process_data,TIMEOUT)
        else:
            for sno,host in enumerate(set(filter(None,hosts_data))):
                print('>%s/%s. Checking on %s' %(sno+1,total_hosts,host))
                p=mp.Process(target=default_fucns,args=(target,host,default))
                p.name = host
                process_data[p] = time.time()
                p.start()
            terminate_on_time(process_data, TIMEOUT)

        for thrd in threads_l:
            thrd.join()

    if args.disk:
        thread_init(disk_space)

    if args.image:
        print('\n\tNOTE:It tells you other Linux hosts info\n\tIf does not return, its a Linux host')
        time.sleep(3)
        thread_init(groupByImage)

    if args.scan:
        thread_init(scanner)

    if args.env:
        thread_init(groupByEnv,default=False)

    if args.host_fqdn:
        thread_init(get_fqdn,default=False)

    if args.os_version:
        thread_init(os_number)

    if args.identity:
        thread_init(get_identity)

    if args.archs:
        thread_init(get_archs)

    if args.region:
        thread_init(groupByRegion,default=False)

    if args.fixidentity:
        thread_init(fix_dentity)

    if args.usermanaged:
        thread_init(getUserManagedHosts,default=False)

    if args.hostinfo:
        thread_init(getAllData,default=False)

    if args.manualexecute:
        if not args.cmd:
            sys.exit('--cmd tag is mandatory along with --manualexecute')
        thread_init(manual_execution,default=False)

    complete_data={
      'Non_prod_hosts'              : Non_prod_hosts,
      'Prod_hosts'                  : Prod_hosts,
      'disk_space_issues'           : disk_space_issues,
      'Rpm_package_issues'          : Rpm_package_issues,
      'host_regions'                : host_regions,
      'Identity_mismatch'           : Identity_mismatch,
      'Solaris_hosts'               : Solaris_hosts,
      'NotWorkedWithStandardPasswd' : NotWorkedWithStandardPasswd,
      'Non_linux_sol'               : Non_linux_sol,
      'Invalid_hosts'               : Invalid_hosts,
      'Host_fqdn'                   : Host_fqdn,
      'Archs_not_supported'         : Archs_not_supported,
      'Misc_issues'                 : Misc_issues,
      'Hosts_down'                  : Hosts_down,
      'Not_supported_os'            : Not_supported_os,
      'Fix_identity_failed'         : Fix_identity_failed,
      'PassWordChangeData'          : PassWordChangeData,
      'PassWordNotChanged'          : PassWordNotChanged,
      'HostInfo'                    : HostInfo,
      'AuthFailed'                  : AuthFailed,
      'UserManaged'                 : UserManaged,
      'NoSudoAccess'                : NoSudoAccess,
      'Success'                     : Success,
      'Low_disk_space'              : Low_disk_space,
      'Behind_firewall'             : Behind_firewall,
      'CMA_failures'                : CMA_failures
     }
    #os.system('clear')

    Consolidated_data = []
    print('\n')
    if len(hosts_data) > 1:
        print('\nHosts break-up, out of %s :' %(len(hosts_data)))

    ''' display file which has data more than zero size and number of lines in a file'''
    for FileName, data in complete_data.items():
        FileName = '%s_%s.log' % (FileName, CURRENT_TIME)
        # print(FileName)
        file_length=0
        try:
            if os.path.exists(FileName):
                file_length=get_number_of_lines(FileName)
                # print(f'file_length : {file_length}')
        except FileNotFoundError:
            pass
        else:
            '''If the output file has atleast one entry, then only it display on screen'''
            if file_length >= 1:
                print(f'\t>>{FileName:30} : {file_length}')

    ''' if consolidate_file exists then only get the lines of numbers in it'''
    consolidate_file=LOGFILE
    if os.path.exists(consolidate_file):
        consolidated_file_lines = get_number_of_lines(consolidate_file)

        '''consolidated_file_lines should have more then one entry to display on screen'''
        if consolidated_file_lines > 0:
           print(f'\n\t> {consolidate_file} : {consolidated_file_lines}')

    if os_number_type.keys():
       print('\tOS Version.\n')
       for host,num in os_number_type.items():
          print('%s --> %s' %(host,num))

if __name__ == '__main__':
   state = True
   main()
   #removing this file was created for monitor purpose
   time.sleep(30)
   try:
      os.remove(f'{LOGFILE}_monitor')
   except Exception as e:
      print(f'WARNING: {LOGFILE}_monitor {str(e)}')


