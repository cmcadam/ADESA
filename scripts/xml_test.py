import xml.etree.ElementTree as ET
from report_dict import REPORT_DICT

if __name__ == '__main__':
    # tree = ET.parse('gpo_report.xml')
    # root = tree.getroot()

    # print(REPORT_DICT['Application Control'])


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

    with open('../proxy_info.txt', encoding='utf-16', errors='ignore') as f:
        lines = f.readlines()
        print(int(lines[3].strip('\n').strip()))
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
