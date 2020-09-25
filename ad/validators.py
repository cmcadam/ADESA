def validIPAddress(IP):

    def isIPv4(s):
        try:
            return str(0 <= int(s) <= 225)
        except:
            return False

    if IP.count('.') == 3 and all(isIPv4(s) for s in IP.split('.')):
        return True
    else:
        return False
