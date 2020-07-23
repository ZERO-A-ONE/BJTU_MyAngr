import re
import os
import struct
from Bin.ReadBin import RB
import Bin.ToolFun

def bytes2hex(bytes):
    num = len(bytes)
    hexstr = u""
    for i in range(num):
        t = u"%x" % bytes[i]
        if len(t) % 2:
            hexstr += u"0"
        hexstr += t
    return hexstr.upper()

filePath = 'D:/大创项目/hello'
if __name__ == '__main__':
    binFile = open(filePath, 'rb')
    print(type(binFile))
    '''
    size = os.path.getsize('D:/大创项目/hello')
    binFile = open(filePath,'rb')
    for i in range(size):
        data = binFile.read(1)  # 每次输出一个字节
        num = struct.unpack('B', data)
        print(hex(num[0]))
    binFile.close()
    '''
    File = RB(filePath)
    data = File.data()
    print(data)
    temp = ""
    for i in range(4):
        temp = Bin.ToolFun.list2hex(data,i)
        print(temp)
        #print()
