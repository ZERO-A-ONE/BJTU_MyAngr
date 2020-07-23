import Bin.ToolFun
FileHead = {
    "52617221": "RAR",
    "504b0304": "ZIP",
    "4d5a": "EXE",
    "7f454c46": "ELF",
    "ffd8ff":   "JPG",
    "89504e47": "PNG",
    "47494638": "GIF",
    "49492a00": "TIF",
    "424d": "BMP",
    "41433130": "DWG",
    "38425053": "PSD",
    "7b5c727466": "RTF",
    "3c3f786d6c": "XML",
    "68746d6c3e": "HTML",
    "44656c69766572792d646174653a": "EML",
    "cfad12fec5fd746f": "DBX",
    "2142444e": "PST",
    "d0cf11e0": "XLS/DOC",
    "5374616e64617264204a": "MDB",
    "ff575043": "WPD",
    "252150532d41646f6265": "EPS/RPS",
    "255044462d312e":   "PDF",
    "000001ba": "MPG",
    "000001b3": "MPG"
}

class File:
    _Type = ""
    _Size = ""
    def __init__(self,data):
        temp = ""
        for i in range(len(data)):
            temp = Bin.ToolFun.list2hex(data, i)
            try:
                self._Type = FileHead[temp]
                break
            except:
                self._Type = "UnKnown"
        self._Size = len(data)

    def type(self):
        return self._Type

