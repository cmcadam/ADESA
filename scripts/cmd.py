import os, time
import re
import paramiko
import xml.etree.ElementTree as ET

from .report_dict import report_dict

gpo_dict = {}

# TODO
def application_control_audit(root):
    print('application control report')

    # user based policies at root[9][3], iterate on the 4th layer for GPO details
    if int(root[9][0].text) == 0:
        print('No user policies applied in this GPO')
    else:
        for i in range(0, len(root[9][3][0])):
            if root[9][3][0][i][0].text == 'Run only specified Windows applications':
                # iterate through each of the specified files
                for j in range(0, len(root[9][3][0][i][5][4])):
                    # check file type contains .exe

                    # check file type contains .ps1

                    # check file type contains .dll

                    # check files match with microsoft block list
                    print(root[9][3][0][i][5][4][j][0].text)
            # else:
            #     print(root[9][3][0][i][0].text)


def patch_application_audit(root):
    pass

# Working
def office_macros_audit(root):
    print('office macro report')
    # user based policies at root[9][3], iterate on the 4th layer for GPO details
    if int(root[9][0].text) == 0:
        print('No user policies applied in this GPO')
    else:
        for i in range(0, len(root[9][3][0])):
            if root[9][3][0][i][0].text == 'Disable Trust Bar Notification for unsigned application add-ins and block them':
                print(root[9][3][0][i][0].text)
            elif root[9][3][0][i][0].text == 'Automation Security':
                print(root[9][3][0][i][0].text)
            elif root[9][3][0][i][0].text == 'Block macros from running in Office files from the Internet':
                print(root[9][3][0][i][0].text)
            elif root[9][3][0][i][0].text == 'Allow mix of policy and user locations':
                print(root[9][3][0][i][0].text)


def application_hardening_audit(root):
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
                print(name.text)
            elif name.text == 'Java permissions':
                print(name.text)
            elif name.text == 'Turn off Adobe Flash in Internet Explorer and prevent applications from using Internet Explorer technology to instantiate Flash objects':
                print(name.text)

        # this is a registry key
        #     elif root[8][3][0][i][0].text == 'Block Flash activation in Office documents':
        #         print(root[8][3][0][i][0].text)



def admin_privileges_audit(root):
    for name in root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
                             '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
                             '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
                             '{http://www.microsoft.com/GroupPolicy/Settings/Auditing}AuditSetting/'
                             '{http://www.microsoft.com/GroupPolicy/Settings/Auditing}SubcategoryName'):
        if name.text == 'Audit Other Privilege Use Events':
            print(name.text)
        elif name.text == 'Audit Sensitive Privilege Use':
            print(name.text)

        # TODO test for existence of a web proxy


def patch_os_audit(root, session, ftp_client):
    execute_command(
        'powershell Get-ADOrganizationalUnit -Filter \'Name -like \\"*\\"\' ^| Format-Table Name, LinkedGroupPolicyObjects -A ^| Out-String -Width 10000 > C:\\ADAudit\\ou_info.txt',
        session)
    getfile('C:\\ADAudit\\ou_info.txt', 'gpo_guids.txt', session, ftp_client)


def mfa_audit(root):
    print('mfa report')
    # computer based policies at root[8][3], iterate on the 4th layer for GPO details
    if int(root[8][0].text) == 0:
        print('No user policies applied in this GPO')
    else:
        for i in range(0, len(root[8][3][0])):
            if root[8][3][0][i][0].text == 'Client: Limit Two-Factor to RDP Logons Only':
                print(root[8][3][0][i][0].text)


def backup_audit(root, session, ftp_client):
    pass


def clean_up_files(session, ftp_client):
    ftp_client.remove('C:\\ADAudit\\ou_info.txt')
    ftp_client.remove('C:\\ADAudit\\GPOReport.xml')
    ftp_client.rmdir('C:\\ADAudit')
    # os.remove('gpo_guids.txt')
    # os.remove('gpo_report.xml')
    ftp_client.close()

def parse_xml(session, ftp_client):
    tree = ET.parse('gpo_report.xml')
    root = tree.getroot()
    # for child in root:
    #     print(child.tag, child.attrib)

    gpo_dict[root[1].text]=root[0][0].text
    print('Currently auditing GPO: {}'.format(root[1].text))

    application_control_audit(root)
    patch_application_audit(root)
    office_macros_audit(root)
    application_hardening_audit(root)
    admin_privileges_audit(root)
    patch_os_audit(root, session, ftp_client)
    mfa_audit(root)
    backup_audit(root, session, ftp_client)

    # computer based policies at root[8][3], iterate on the 4th layer for GPO details
    # if int(root[8][0].text) == 0:
    #     print('No computer policies applied in this GPO')
    # else:
    #     for i in range(0, len(root[8][3][0])):
    #         print(root[8][3][0][i][0].text)

    # user based policies at root[9][3], iterate on the 4th layer for GPO details
    # if int(root[9][0].text) == 0:
    #     print('No user policies applied in this GPO')
    # else:
    #     for i in range(0, len(root[9][3][0])):
    #         if root[9][3][0][i][0].text == 'Run only specified Windows applications':
    #             print(root[9][3][0][i][5][4][0][0].text)
    #         else:
    #             print(root[9][3][0][i][0].text)



def getfile(filepath, local_filename, session, ftp_client):
    ftp_client.get(filepath, local_filename)

def execute_command(command, session):
    stdin, stdout, stderr = session.exec_command(command)
    time.sleep(5)
    # print("stdin: {}".format(stdin.read()))
    # print("stdout: {}".format(stdout.read()))
    # print("stderr: {}".format(stderr.read()))


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

# if __name__=='__main__':
def get_ad_info(address, username, password):
    paramiko.util.log_to_file("paramiko.log")

    # dictionaries to store the results of the processed data from the server    
    ou_dict = {}
    print('Connecting to target server...')
    try:
        session, ftp_client = connect_to_server(address, username, password)
    except:
        raise ValueError('could not connect to the server')
    # session, ftp_client = connect_to_server('10.1.10.2')
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
    
    # parse_xml()
    print(gpo_dict)

    # clean up all the files created on the server to ensure that sensitive AD info is never leaked
    clean_up_files(session, ftp_client)
