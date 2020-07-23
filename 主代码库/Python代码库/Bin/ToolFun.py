#字节码转16进制字符串
def bytes2hex(bytes):
    num = len(bytes)
    hexstr = u""
    for i in range(num):
        t = u"%x" % bytes[i]
        if len(t) % 2:
            hexstr += u"0"
        hexstr += t
    return hexstr.upper()
#列表转16进制字符串
def list2hex(list,len):
    temp = ""
    for i in range(len):
        tmp = str(hex(list[i]))
        tmp = tmp[2:]
        temp += tmp
    return temp