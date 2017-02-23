import ctypes, sys
from ctypes import windll, wintypes
from uuid import UUID
import win32com.shell.shell

class GUID(ctypes.Structure):   # [1]
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8)
    ] 

    def __init__(self, uuid_):
        ctypes.Structure.__init__(self)
        self.Data1, self.Data2, self.Data3, self.Data4[0], self.Data4[1], rest = uuid_.fields
        for i in range(2, 8):
            self.Data4[i] = rest>>(8 - i - 1)*8 & 0xff

class UserHandle:   # [3]
    current = wintypes.HANDLE(0)
    common  = wintypes.HANDLE(-1)

_CoTaskMemFree = windll.ole32.CoTaskMemFree     # [4]
_CoTaskMemFree.restype= None
_CoTaskMemFree.argtypes = [ctypes.c_void_p]

_SHGetKnownFolderPath = windll.shell32.SHGetKnownFolderPath     # [5] [3]
_SHGetKnownFolderPath.argtypes = [
    ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)
] 

class PathNotFoundException(Exception): pass

def get_path(folderid, user_handle=UserHandle.current):
    fid = GUID(UUID(str(getattr(win32com.shell.shell, 'FOLDERID_' + folderid))))
    pPath = ctypes.c_wchar_p()
    S_OK = 0
    if _SHGetKnownFolderPath(fid, 0, user_handle, ctypes.byref(pPath)) != S_OK:
        raise PathNotFoundException()
    path = pPath.value
    _CoTaskMemFree(pPath)
    return path

# [1] http://msdn.microsoft.com/en-us/library/windows/desktop/aa373931.aspx
# [2] http://msdn.microsoft.com/en-us/library/windows/desktop/dd378457.aspx
# [3] http://msdn.microsoft.com/en-us/library/windows/desktop/bb762188.aspx
# [4] http://msdn.microsoft.com/en-us/library/windows/desktop/ms680722.aspx
# [5] http://www.themacaque.com/?p=954