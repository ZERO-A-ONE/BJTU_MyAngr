import os
import struct

class RB:

    _filePath = ""
    _data = []
    _size = ""

    def __init__(self,Path):
        self._filePath = Path
        self._size = os.path.getsize(Path)
        binfile = open(self._filePath,'rb')
        for i in range(self._size):
            tmp = binfile.read(1)  # 每次读取一个字节
            num = struct.unpack('B', tmp)
            self._data.append(num[0])

    def data(self):
        return self._data

    #返回读取的文件路径
    def filename(self):
        return self._filePath

    def size(self):
        return self._size

    def byte(self):
        return open(self._filePath,'rb')
