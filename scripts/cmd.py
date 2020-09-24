import os, time
import re
import paramiko
import xml.etree.ElementTree as ET

gpo_dict = {}

def clean_up_files(session, ftp_client):
    ftp_client.remove('C:\\ADAudit\\ou_info.txt')
    ftp_client.remove('C:\\ADAudit\\GPOReport.xml')
    ftp_client.rmdir('C:\\ADAudit')
    os.remove('gpo_guids.txt')
    os.remove('gpo_report.xml')
    ftp_client.close()

# TODO view all the applied group policies
def policy_auditor():
    pass

def parse_xml():
    tree = ET.parse('gpo_report.xml')
    root = tree.getroot()
    # for child in root:
    #     print(child.tag, child.attrib)

    gpo_dict[root[1].text]=root[0][0].text
    print('Currently auditing GPO: {}'.format(root[1].text))

    # computer based policies at root[8][3], iterate on the 4th layer for GPO details
    if int(root[8][0].text) == 0:
        print('No computer policies applied in this GPO')
    else:
        for i in range(0, len(root[8][3][0])):
            print(root[8][3][0][i][0].text)

    # user based policies at root[9][3], iterate on the 4th layer for GPO details
    if int(root[9][0].text) == 0:
        print('No user policies applied in this GPO')
    else:
        for i in range(0, len(root[9][3][0])):
            print(root[9][3][0][i][0].text)



def getfile(filepath, local_filename, session, ftp_client):
    ftp_client.get(filepath, local_filename)

def execute_command(command, session):
    stdin, stdout, stderr = session.exec_command(command)
    time.sleep(5)
    # print("stdin: {}".format(stdin.read()))
    # print("stdout: {}".format(stdout.read()))
    # print("stderr: {}".format(stderr.read()))


def connect_to_server(server):
    ssh = paramiko.SSHClient()
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
        print('Failed to connect to server')
        return

if __name__=='__main__':
    paramiko.util.log_to_file("paramiko.log")

    # dictionaries to store the results of the processed data from the server    
    ou_dict = {}

    print('Connecting to target server...')
    session, ftp_client = connect_to_server('10.1.10.2')
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
            parse_xml()
    
    # parse_xml()
    print(gpo_dict)

    # clean up all the files created on the server to ensure that sensitive AD info is never leaked
    clean_up_files(session, ftp_client)
