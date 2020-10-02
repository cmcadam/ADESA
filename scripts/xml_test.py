import xml.etree.ElementTree as ET

if __name__ == '__main__':
    tree = ET.parse('gpo_report.xml')
    root = tree.getroot()
    # for child in root:
    #     print(child.tag, child.attrib)

    print(root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
                       '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
                       '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
                       '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Policy/'
                       '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name'
                       ))
    for name in root.findall('.//{http://www.microsoft.com/GroupPolicy/Settings}Computer/'
                       '{http://www.microsoft.com/GroupPolicy/Settings}ExtensionData/'
                       '{http://www.microsoft.com/GroupPolicy/Settings}Extension/'
                       '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Policy/'
                       '{http://www.microsoft.com/GroupPolicy/Settings/Registry}Name'
                    ):
        print(name.text)
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
