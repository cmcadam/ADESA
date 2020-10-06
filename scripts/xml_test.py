import xml.etree.ElementTree as ET
from report_dict import REPORT_DICT
from datetime import datetime

if __name__ == '__main__':
    # tree = ET.parse('gpo_report.xml')
    # root = tree.getroot()

    # print(REPORT_DICT['Application Control'])
    print('Backup Audit')
    # TODO fix command and add logic once file is read
    # Get all backup information on the server

    # execute_command('powershell WBAdmin ENABLE BACKUP ^| Out-File C:\\ADAudit\\backup_info.txt', session)
    # getfile('C:\\ADAudit\\backup_info.txt', 'backup_info.txt', session, ftp_client)

    try:
        with open('../backup_info.txt', encoding='utf-16', errors='ignore') as f:
            lines = f.readlines()
            if 'The scheduled backup settings:' == lines[3].strip('\n').strip():
                pass
                # current_report_result['Daily Backups']['Maturity Level 1']['Control 1']['Policy Score'] = 1
                # current_report_result['Daily Backups']['Maturity Level 2']['Control 1']['Policy Score'] = 1
                # current_report_result['Daily Backups']['Maturity Level 3']['Control 1']['Policy Score'] = 1
    except:
        print('Unable to get backup information from server')

    # execute_command('powershell WBAdmin GET VERSIONS ^| Out-File C:\\ADAudit\\backup_files.txt', session)
    # getfile('C:\\ADAudit\\backup_files.txt', 'backup_files.txt', session, ftp_client)

    try:
        with open('../backup_files.txt', encoding='utf-16', errors='ignore') as f:
            lines = f.readlines()
            for i in range(0, len(lines)):
                if lines[i][:11] == 'Backup time':
                    backup_date = datetime.strptime(lines[i][13:][:9], '%m/%d/%Y')
                    current_date = datetime.now()
                    res = current_date - backup_date
                    print(res.days)
                    print(current_date)

        if None:
            pass
            # current_report_result['Daily Backups']['Maturity Level 1']['Control 2']['Policy Score'] = 1
            # current_report_result['Daily Backups']['Maturity Level 2']['Control 2']['Policy Score'] = 1
            # current_report_result['Daily Backups']['Maturity Level 2']['Control 3']['Policy Score'] = 1
            # current_report_result['Daily Backups']['Maturity Level 3']['Control 2']['Policy Score'] = 1
            # current_report_result['Daily Backups']['Maturity Level 3']['Control 3']['Policy Score'] = 1

    except:
        print('Unable to get backup info from the server')

    # Get info of all running vms on the server

    # TODO make sure this file doesnt return blank


    try:
        with open('../vm_info.txt', encoding='utf-16', errors='ignore') as f:
            lines = f.readlines()
            for i in range(0, len(lines)):
                print(lines[i])
                if None:
                    pass
                    # current_report_result['Daily Backups']['Maturity Level 2']['Control 4']['Policy Score'] = 1
                    # current_report_result['Daily Backups']['Maturity Level 2']['Control 5']['Policy Score'] = 1
                    # current_report_result['Daily Backups']['Maturity Level 3']['Control 4']['Policy Score'] = 1
                    # current_report_result['Daily Backups']['Maturity Level 3']['Control 5']['Policy Score'] = 1
    except:
        print('Unable to get VM info from the server')

    # with open('../client_os_info.txt', encoding='utf-16', errors='ignore') as f:
    #     lines = f.readlines()
    #     for i in range(3, len(lines)):
    #         if lines[i].strip('\n').strip().split(' ')[0] != '':
    #             os_version = float(lines[i].strip('\n').strip().split(' ')[-2])
    #             print(os_version)
    # with open('../os_patching_info.txt', encoding='utf-16', errors='ignore') as f:
    #     lines = f.readlines()
    #     for i in range(0, len(lines)):
    #         print(lines[i].strip('\n'))

    # with open('../proxy_info.txt', encoding='utf-16', errors='ignore') as f:
    #     lines = f.readlines()
    #     print(int(lines[3].strip('\n').strip()))
    # for maturity_level in REPORT_DICT['Application Control']:
    #     for control in REPORT_DICT['Application Control'][maturity_level]:
    #         print(REPORT_DICT['Application Control'][maturity_level][control]['Control Name'])

    # for child in root:
    #     print(child.tag, child.attrib)

    # print(root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Policy/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name'
    #                    ))
    # for name in root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Policy/'
    #                    '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name'
    #                 ):
    #     print(name.text)
    # print(root.findall('.//*AuditSetting/PolicyTarget'))

    # Location of registry keys
    # root[8][3][0][0][0][2][3][2][2][2][2][1].attrib['key']

    # computer based policies at root[8][3], iterate on the 4th layer for GPO details
    # if int(root[9][0].text) == 0:
    #     print('No computer policies applied in this GPO')
    # else:
    #     for i in range(0, len(root[9][3][0])):
    #         if root[9][3][0][i][0].text == 'Run only specified Windows applications':
    #             print(root[9][3][0][i][5][4][0][0].text)
    #         else:
    #             print(root[9][3][0][i][0].text)
