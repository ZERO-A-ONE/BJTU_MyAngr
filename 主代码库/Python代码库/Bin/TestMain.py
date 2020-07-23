from Bin.CheckBin import File
from Bin.ReadBin import RB
import Bin.ReadELF
from Bin.BinInfo import BinInfo

FileHead = {
    "52617221": "RAR",
    "504b0304": "EXT_ZIP",
    "4d5a": "EXE",
    "7f454c46": "ELF"
}

filePath = 'D:/大创项目/hello'
file_path = "C:/Program Files (x86)/Dev-Cpp/devcpp.exe"
if __name__ == '__main__':
    '''
    binFile = open(filePath, 'rb')
    print(type(binFile))
    '''

    '''
    size = os.path.getsize('D:/大创项目/hello')
    binFile = open(filePath,'rb')
    for i in range(size):
        data = binFile.read(1)  # 每次输出一个字节
        num = struct.unpack('B', data)
        print(hex(num[0]))
    binFile.close()
    '''

    '''
    Fi = RB(filePath)
    data = Fi.data()
    print(data)
    temp = ""
    for i in range(File.size()):
        temp = Bin.ToolFun.list2hex(data,i)
        print(temp)
        try:
            print(FileHead[temp])
            break
        except:
            print("Null")
    F = File(data)
    print(F.type())
    binFile = open(filePath, 'rb')
    Bin.ReadELF.readelf(binFile)
    '''
    NewBin = BinInfo(file_path)
    NewBin.Pinfo()