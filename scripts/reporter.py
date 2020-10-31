import os, time
import re
from datetime import datetime
import paramiko
import xml.etree.ElementTree as ET

from scripts.report_dict import REPORT_DICT

current_report_result = REPORT_DICT
gpo_dict = {}


# Done
def application_control_audit(root):
    # create the flags for the file extensions
    exe_flag = 0
    ps1_flag = 0
    dll_flag = 0

    block_list_count = 0

    # user based policies at root[9][3], iterate on the 4th layer for GPO details
    if int(root[9][0].text) == 0:
        print('No user policies applied in this GPO')
    else:
        file_list = []
        f = open('ms_block_list.txt', 'r')
        lines = f.readlines()
        for line in lines:
            file_list.append(line.strip('\n'))

        for i in range(0, len(root[9][3][0])):
            if root[9][3][0][i][0].text == 'Run only specified Windows applications':
                # iterate through each of the specified files
                for j in range(0, len(root[9][3][0][i][5][4])):
                    # check file type contains .exe
                    if '.exe' in root[9][3][0][i][5][4][j][0].text:
                        exe_flag = 1
                    # check file type contains .ps1
                    if '.ps1' in root[9][3][0][i][5][4][j][0].text:
                        ps1_flag = 1
                    # check file type contains .dll
                    if '.dll' in root[9][3][0][i][5][4][j][0].text:
                        dll_flag = 1
                    # check files match with microsoft block list
                    if root[9][3][0][i][5][4][j][0].text in file_list:
                        block_list_count += 1

        # Update result dictionary
        if exe_flag == 1:
            current_report_result['Application Control']['Maturity Level 1']['Control 1']['Policy Score'] = 1
            current_report_result['Application Control']['Maturity Level 1']['Control 2']['Policy Score'] = 1
        if exe_flag and ps1_flag == 1:
            current_report_result['Application Control']['Maturity Level 2']['Control 1']['Policy Score'] = 1
            current_report_result['Application Control']['Maturity Level 2']['Control 2']['Policy Score'] = 1
        if exe_flag and ps1_flag and dll_flag == 1:
            current_report_result['Application Control']['Maturity Level 3']['Control 1']['Policy Score'] = 1
            current_report_result['Application Control']['Maturity Level 3']['Control 2']['Policy Score'] = 1
        if block_list_count == len(file_list):
            current_report_result['Application Control']['Maturity Level 3']['Control 3']['Policy Score'] = 1


# Done
def office_macros_audit(root):
    # user based policies at root[9][3], iterate on the 4th layer for GPO details
    if int(root[9][0].text) == 0:
        print('No user policies applied in this GPO')
    else:
        for i in range(0, len(root[9][3][0])):
            if root[9][3][0][i][0].text == 'Disable Trust Bar Notification for unsigned application add-ins and block them':
                current_report_result['Microsoft Office Macros']['Maturity Level 1']['Control 1']['Policy Score'] = 1
            if root[9][3][0][i][0].text == 'Automation Security':
                current_report_result['Microsoft Office Macros']['Maturity Level 1']['Control 2']['Policy Score'] = 1
                current_report_result['Microsoft Office Macros']['Maturity Level 2']['Control 3']['Policy Score'] = 1
                current_report_result['Microsoft Office Macros']['Maturity Level 3']['Control 3']['Policy Score'] = 1
            if root[9][3][0][i][0].text == 'Block macros from running in Office files from the Internet':
                current_report_result['Microsoft Office Macros']['Maturity Level 2']['Control 2']['Policy Score'] = 1
                current_report_result['Microsoft Office Macros']['Maturity Level 3']['Control 2']['Policy Score'] = 1
            if root[9][3][0][i][0].text == 'Allow mix of policy and user locations':
                current_report_result['Microsoft Office Macros']['Maturity Level 2']['Control 1']['Policy Score'] = 1
                current_report_result['Microsoft Office Macros']['Maturity Level 3']['Control 1']['Policy Score'] = 1


# Done
def application_hardening_audit(root, session, ftp_client):
    print('application hardening report')
    # computer based policies at root[8][3], iterate on the 4th layer for GPO details
    if int(root[8][0].text) == 0:
        print('No computer policies applied in this GPO')
    else:
        # locate the policies for blocking pop ups and java
        for name in root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Policy/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name'
                                 ):
            if name.text == 'Block popups':
                current_report_result['User Application Hardening']['Maturity Level 2']['Control 2']['Policy Score'] = 1
                current_report_result['User Application Hardening']['Maturity Level 3']['Control 2']['Policy Score'] = 1
            if name.text == 'Java permissions':
                current_report_result['User Application Hardening']['Maturity Level 2']['Control 3']['Policy Score'] = 1
                current_report_result['User Application Hardening']['Maturity Level 3']['Control 3']['Policy Score'] = 1
            if name.text == 'Turn off Adobe Flash in Internet Explorer and prevent applications from using Internet Explorer technology to instantiate Flash objects':
                current_report_result['User Application Hardening']['Maturity Level 1']['Control 1']['Policy Score'] = 1
                current_report_result['User Application Hardening']['Maturity Level 2']['Control 1']['Policy Score'] = 1
                current_report_result['User Application Hardening']['Maturity Level 3']['Control 1']['Policy Score'] = 1
            if name.text == 'Block Flash activation in Office documents':
                current_report_result['User Application Hardening']['Maturity Level 3']['Control 4']['Policy Score'] = 1

    # Find the registry key to prevent object linking
    execute_command(
        'powershell Get-ItemProperty -Path \\"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\" ^| Format-Table ProxyEnable ^| Out-File C:\\ADAudit\\object_linking_info.txt',
        session)
    getfile('C:\\ADAudit\\object_linking_info.txt', 'object_linking_info.txt', session, ftp_client)

    # check if the registry key exists
    with open('object_linking_info.txt', encoding='utf-16', errors='ignore') as f:
        lines = f.readlines()
        if len(lines) != 0:
            current_report_result['User Application Hardening']['Maturity Level 3']['Control 5']['Policy Score'] = 1


# Done
def admin_privileges_audit(root, session, ftp_client):
    for name in root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
                             '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
                             '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
                             '{http://www.microsoft.com/GroupPolicy/Settings/Auditing}AuditSetting/'
                             '{http://www.microsoft.com/GroupPolicy/Settings/Auditing}SubcategoryName'):
        if name.text == 'Audit Other Privilege Use Events':
            current_report_result['Restrict Administrative Privileges']['Maturity Level 1']['Control 2']['Policy Score'] = 1
            current_report_result['Restrict Administrative Privileges']['Maturity Level 2']['Control 2']['Policy Score'] = 1
            current_report_result['Restrict Administrative Privileges']['Maturity Level 3']['Control 2']['Policy Score'] = 1
        if name.text == 'Audit Sensitive Privilege Use':
            current_report_result['Restrict Administrative Privileges']['Maturity Level 1']['Control 1']['Policy Score'] = 1
            current_report_result['Restrict Administrative Privileges']['Maturity Level 2']['Control 1']['Policy Score'] = 1
            current_report_result['Restrict Administrative Privileges']['Maturity Level 3']['Control 1']['Policy Score'] = 1

    execute_command('powershell Get-ItemProperty -Path \\"Registry::HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\" ^| Format-Table ProxyEnable ^| Out-File C:\\ADAudit\\proxy_info.txt', session)
    getfile('C:\\ADAudit\\proxy_info.txt', 'proxy_info.txt', session, ftp_client)

    with open('proxy_info.txt', encoding='utf-16', errors='ignore') as f:
        lines = f.readlines()
        try:
            if int(lines[3].strip('\n').strip()) == 1:
                current_report_result['Restrict Administrative Privileges']['Maturity Level 3']['Control 3'][
                    'Policy Score'] = 1
        except:
            print('No proxy enabled')


# Done
def patch_os_audit(session, ftp_client):
    client_os_flag = 1
    server_os_flag = 1

    # Read the servers operating system
    execute_command('powershell (Get-CimInstance Win32_OperatingSystem).version ^| Out-File C:\\ADAudit\\os_patching_info.txt', session)
    # Get info for all the client computers operating systems
    execute_command(
        'powershell Get-ADComputer -Filter * -Property * ^| Format-Table Name,OperatingSystem,OperatingSystemVersion ^| Out-File C:\\ADAudit\\client_os_info.txt',
        session)
    # Get the results of the powershell scripts
    getfile('C:\\ADAudit\\client_os_info.txt', 'client_os_info.txt', session, ftp_client)
    getfile('C:\\ADAudit\\os_patching_info.txt', 'os_patching_info.txt', session, ftp_client)

    try:
        with open('os_patching_info.txt', encoding='utf-16', errors='ignore') as f:
            lines = f.readlines()
            for i in range(0, len(lines)):
                server_os_version = lines[i].strip('\n')
                if int(server_os_version.split('.')[0]) < 10:
                    server_os_flag = 0
    except:
        print('Unable to get OS patching info')
    try:
        with open('client_os_info.txt', encoding='utf-16', errors='ignore') as f:
            lines = f.readlines()
            for i in range(4, len(lines)):
                if lines[i].strip('\n').strip().split(' ')[0] != '':
                    os_version = float(lines[i].strip('\n').strip().split(' ')[-2])
                    if os_version < 10.0:
                        client_os_flag = 0
    except:
        print('Unable to read client OS info')

    if client_os_flag == 1:
        current_report_result['Patch Operating Systems']['Maturity Level 1']['Control 2'][
            'Policy Score'] = 1
        current_report_result['Patch Operating Systems']['Maturity Level 2']['Control 2'][
            'Policy Score'] = 1
        current_report_result['Patch Operating Systems']['Maturity Level 3']['Control 3'][
            'Policy Score'] = 1
    if server_os_flag == 1:
        current_report_result['Patch Operating Systems']['Maturity Level 1']['Control 1'][
            'Policy Score'] = 1
        current_report_result['Patch Operating Systems']['Maturity Level 2']['Control 1'][
            'Policy Score'] = 1
        current_report_result['Patch Operating Systems']['Maturity Level 3']['Control 1'][
            'Policy Score'] = 1


# Done
def mfa_audit(root):
    # computer based policies at root[8][3], iterate on the 4th layer for GPO details
    if int(root[8][0].text) == 0:
        print('No user policies applied in this GPO')
    else:
        for name in root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Policy/'
                                 '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name'
                                 ):
            if name.text == 'Client: Limit Two-Factor to RDP Logons Only':
                current_report_result['Multi-factor Authentication']['Maturity Level 1']['Control 1']['Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 1']['Control 2'][
                    'Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 2']['Control 1'][
                    'Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 2']['Control 2'][
                    'Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 2']['Control 3'][
                    'Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 3']['Control 1'][
                    'Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 3']['Control 2'][
                    'Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 3']['Control 3'][
                    'Policy Score'] = 1
                current_report_result['Multi-factor Authentication']['Maturity Level 3']['Control 4'][
                    'Policy Score'] = 1


# Done
def patch_application_audit(session, ftp_client):
    # Run powershell scripts on server
    execute_command('powershell Get-WsusServer ^| Out-File C:\\ADAudit\\wsus_info.txt', session)
    execute_command('powershell (Get-ADComputer -Filter *).Name ^| Out-File C:\\ADAudit\\domain_computer_list.txt', session)
    execute_command('powershell Get-CimInstance -ComputerName (Get-Content C:\\ADAudit\\domain_computer_list.txt) -ClassName win32_product -ErrorAction SilentlyContinue ^| Select-Object PSComputerName, Name, PackageName, InstallDate ^| Out-File C:\\ADAudit\\application_patching_info.txt', session)
    # Get the results of the powershell scripts
    getfile('C:\\ADAudit\\application_patching_info.txt', 'application_patching_info.txt', session, ftp_client)
    getfile('C:\\ADAudit\\wsus_info.txt', 'wsus_info.txt', session, ftp_client)

    try:
        with open('application_patching_info.txt') as f:
            lines = f.readlines()
            # remote management has been installed
            if len(lines) != 0:
                current_report_result['Patch Applications']['Maturity Level 1']['Control 2'][
                    'Policy Score'] = 1
                current_report_result['Patch Applications']['Maturity Level 2']['Control 2'][
                    'Policy Score'] = 1
                current_report_result['Patch Applications']['Maturity Level 3']['Control 3'][
                    'Policy Score'] = 1
    except:
        print('Unable to read application patching information')
    try:
        with open('wsus_info.txt') as f:
            lines = f.readlines()
            if len(lines) != 0:
                current_report_result['Patch Applications']['Maturity Level 1']['Control 1'][
                    'Policy Score'] = 1
                current_report_result['Patch Applications']['Maturity Level 2']['Control 1'][
                    'Policy Score'] = 1
                current_report_result['Patch Applications']['Maturity Level 3']['Control 1'][
                    'Policy Score'] = 1
    except:
        print('Unable to read WSUS information')


# Done
def backup_audit(session, ftp_client):
    # Get all backup information on the server
    execute_command('powershell WBAdmin ENABLE BACKUP ^| Out-File C:\\ADAudit\\backup_info.txt', session)
    getfile('C:\\ADAudit\\backup_info.txt', 'backup_info.txt', session, ftp_client)

    with open('backup_info.txt', encoding='utf-16', errors='ignore') as f:
        lines = f.readlines()
        if 'The scheduled backup settings:' == lines[3].strip('\n').strip():
            current_report_result['Daily Backups']['Maturity Level 1']['Control 1']['Policy Score'] = 1
            current_report_result['Daily Backups']['Maturity Level 2']['Control 1']['Policy Score'] = 1
            current_report_result['Daily Backups']['Maturity Level 3']['Control 1']['Policy Score'] = 1

    execute_command('powershell WBAdmin GET VERSIONS ^| Out-File C:\\ADAudit\\backup_files.txt', session)
    getfile('C:\\ADAudit\\backup_files.txt', 'backup_files.txt', session, ftp_client)

    with open('backup_files.txt', encoding='utf-16', errors='ignore') as f:
        lines = f.readlines()
        for i in range(0, len(lines)):
            if lines[i][:11] == 'Backup time':
                backup_date = datetime.strptime(lines[i][13:][:10].strip(), '%m/%d/%Y')
                current_date = datetime.now()
                res = current_date - backup_date
                if res.days >= 90:
                    current_report_result['Daily Backups']['Maturity Level 3']['Control 3']['Policy Score'] = 1
                    current_report_result['Daily Backups']['Maturity Level 3']['Control 2']['Policy Score'] = 1
                elif res.days >= 30 and res.days < 90:
                    current_report_result['Daily Backups']['Maturity Level 2']['Control 2']['Policy Score'] = 1
                    current_report_result['Daily Backups']['Maturity Level 2']['Control 3']['Policy Score'] = 1
                else:
                    current_report_result['Daily Backups']['Maturity Level 1']['Control 2']['Policy Score'] = 1

    # Get info of all running vms on the server
    execute_command('powershell Get-VM ^| Out-File C:\\ADAudit\\vm_info.txt', session)
    getfile('C:\\ADAudit\\vm_info.txt', 'vm_info.txt', session, ftp_client)

    with open('vm_info.txt', encoding='utf-16', errors='ignore') as f:
        lines = f.readlines()
        if len(lines) != 0:
            current_report_result['Daily Backups']['Maturity Level 2']['Control 4']['Policy Score'] = 1
            current_report_result['Daily Backups']['Maturity Level 2']['Control 5']['Policy Score'] = 1
            current_report_result['Daily Backups']['Maturity Level 3']['Control 4']['Policy Score'] = 1
            current_report_result['Daily Backups']['Maturity Level 3']['Control 5']['Policy Score'] = 1


def clean_up_files(ftp_client):
    # ftp_client.remove('C:\Audit')

    # remove all the files from the server the script is running on
    os.remove('gpo_guids.txt')
    os.remove('proxy_info.txt')
    os.remove('gpo_report.xml')
    os.remove('backup_files.txt')
    os.remove('application_patching_info.txt')
    os.remove('backup_info.txt')
    os.remove('os_patching_info.txt')
    os.remove('vm_info.txt')
    os.remove('wsus_info.txt')
    os.remove('client_os_info.txt')
    os.remove('object_linking_info.txt')
    ftp_client.close()


def parse_xml(session, ftp_client):
    tree = ET.parse('gpo_report.xml')
    root = tree.getroot()

    gpo_dict[root[1].text]=root[0][0].text
    print('Currently auditing GPO: {}'.format(root[1].text))

    # Audit categories run once per GPO applied to the server
    application_control_audit(root)
    office_macros_audit(root)
    application_hardening_audit(root, session, ftp_client)
    admin_privileges_audit(root, session, ftp_client)
    mfa_audit(root)


def getfile(filepath, local_filename, session, ftp_client):
    ftp_client.get(filepath, local_filename)


def execute_command(command, session):
    session.exec_command(command)
    time.sleep(5)


def connect_to_server(server, username, password):
    ssh = paramiko.SSHClient()
    if os.getenv('SERVER_USERNAME') and os.getenv('SERVER_PASSWORD'):
        print('found environment variables')
        username = os.environ['SERVER_USERNAME']
        password = os.environ['SERVER_PASSWORD']
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server, username=username, password=password)
        print('Successfully connected to the server')
        ftp_client = ssh.open_sftp()
        ftp_client.mkdir('C:\\ADAudit')
        return ssh, ftp_client
    except:
        raise ValueError('Failed to connect to server with credentials')


def get_ad_info(address, username, password):
    paramiko.util.log_to_file("paramiko.log")

    # dictionaries to store the results of the processed data from the server    
    ou_dict = {}
    print('Connecting to target server...')
    try:
        session, ftp_client = connect_to_server(address, username, password)
    except:
        raise ValueError('could not connect to the server')

    print('Reading GPO\'s....')

    try:
        execute_command('powershell Get-ADOrganizationalUnit -Filter \'Name -like \\"*\\"\' ^| Format-Table Name, LinkedGroupPolicyObjects -A ^| Out-String -Width 10000 > C:\\ADAudit\\ou_info.txt', session)
        getfile('C:\\ADAudit\\ou_info.txt', 'gpo_guids.txt', session, ftp_client)
        print('Successfully read GPO\'s from target server')
    except:
        print('Unable to read GPO\'s on target server')

    # read the parse the gpo ids and add them to the gpo dictionary
    try:
        with open('gpo_guids.txt') as f:
            lines = f.readlines()[3:]
            for i in range(0, len(lines)):
                line = lines[i].strip('\n').split('=')
                if len(line) >= 2:
                    gpo_guid_list = []
                    ou_name = line[0][:-3].strip()
                    for j in range(0, int(len(line)/5)):
                        gpo_guid_list.append(re.sub('[{},]', '', line[j * 5 + 1][:-3]))
                    ou_dict[ou_name] = gpo_guid_list
    except:
        print('Unable to read GPO GUID\'s')

    print('Iterating through GPO\'s...')
    
    # go through each of the gpos that returned from the server and check what policies are applied
    for ou in ou_dict:
        for gpo_guid in ou_dict[ou]:
            # execute commands on the server
            execute_command('powershell Get-GPOReport -GUID {} -ReportType XML -Path C:\\ADAudit\\GPOReport.xml'.format(gpo_guid), session)
            # get report file off the server
            getfile('C:\\ADAudit\\GPOReport.xml', 'gpo_report.xml', session, ftp_client)
            parse_xml(session, ftp_client)


    # Audit categories that get run once per audit
    patch_application_audit(session, ftp_client)
    patch_os_audit(session, ftp_client)
    backup_audit(session, ftp_client)

    # clean up all the files created on the server to ensure that sensitive AD info is never leaked
    clean_up_files(ftp_client)

    return current_report_result
