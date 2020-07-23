from Bin.CheckBin import File
from Bin.ReadBin import RB
import Bin.ReadELF
import Bin.ReadPE

class BinInfo:
    _filePath = ""
    _data = []
    _size = ""
    _type = ""

    def __init__(self,path):
        self._filePath = path
        newRB = RB(path)
        self._data = newRB.data()
        self._size = newRB.size()
        newFile = File(self._data)
        self._type = newFile.type()

    def Pinfo(self):
        print("Path: "+self._filePath)
        print("Type: "+self._type)
        print("Size: "+str(self._size)+" Bytes")
        if self._type == "ELF":
            try:
                Bin.ReadELF.readelf(self._filePath)
            except:
                print("Open ELF File Fail!")
        if self._type == "EXE":
            try:
                Bin.ReadPE.readpe(self._filePath)
            except:
                print("Open PE File Fail!")





