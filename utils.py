#Utilities primarily for dealing with windows
import logging
logger = logging.getLogger('bethmetamod.utils')
logging.basicConfig()

import sys
import os
import time
import shutil

import re
import hashlib
import subprocess

from pathlib import Path
from collections import namedtuple

import winreg
import win32api
import win32com.client
import win32com.shell
import ntfsutils.fs

import requests
import psutil
from tqdm import tqdm

import asyncio
import async_timeout
from asyncio_extras.contextmanager import async_contextmanager

BIN_PATH = Path(__file__).parent / 'bin'

def get_regkey(root, sub_key, name):
	from winreg import HKEY_LOCAL_MACHINE as HKLM
	from winreg import HKEY_CURRENT_USER as HKCU
	root = {'HKLM': HKLM, 'HKCU': HKCU}[root]
	return winreg.QueryValueEx(winreg.OpenKey(root, sub_key), name)[0]

class Version(namedtuple('_Version', ('major', 'minor', 'build', 'private'))):
	def __str__(self):
		return '{}.{}.{}.{}'.format(*self)
	
	def __repr__(self):
		return str(self)

def get_fileversion(filename):
	#http://stackoverflow.com/a/1237635/358960
	from win32api import GetFileVersionInfo, LOWORD, HIWORD
	
	try:
		info = GetFileVersionInfo(str(filename), "\\")
		ms = info['FileVersionMS']
		ls = info['FileVersionLS']
		return Version(HIWORD (ms), LOWORD (ms), HIWORD (ls), LOWORD (ls))
	except:
		return Version(0,0,0,0)

def hash_file(hashalg, file):
	import functools
	
	if isinstance(file, str):
		with open(file, 'rb') as f:
			return hash_file(hashalg, f)
	elif isinstance(file, Path):
		with file.open('rb') as f:
			return hash_file(hashalg, f)

	h = hashlib.new(hashalg)
	for chunk in iter(functools.partial(file.read, 4096), b''):
		h.update(chunk)
	return h.hexdigest()
	
def get_file_id(path):
	#TODO posix
	if isinstance(path, Path):
		path = str(path)
		
	f = ntfsutils.fs.getfileinfo(path)
	return (
		f.nFileIndexHigh, f.nFileIndexLow, f.dwVolumeSerialNumber,
		f.nFileSizeHigh, f.nFileSizeLow
	)
		

def sha256_path(path):
	return hash_file('sha256', path)

def is_user_admin():
	#import ctypes
	#return ctypes.windll.shell32.IsUserAnAdmin() != 0
	import win32security

	WinBuiltinAdministratorsSid = 26  # not exported by win32security. according to WELL_KNOWN_SID_TYPE enumeration from http://msdn.microsoft.com/en-us/library/windows/desktop/aa379650%28v=vs.85%29.aspx
	admins = win32security.CreateWellKnownSid(WinBuiltinAdministratorsSid)

	return win32security.CheckTokenMembership(None, admins)

def get_special_folder(folder_name):
	csidl = getattr(shellcon, 'CSIDL_' + folder_name.upper())
	return win32com.shell.shell.SHGetFolderPath(0, csidl, 0, 0)
	
def run_as_admin(cmd, params):
	if os.name != 'nt':
		raise RuntimeError("This function is only implemented on Windows.")

	import win32api, win32con, win32event, win32process
	from win32com.shell.shell import ShellExecuteEx
	from win32com.shell import shellcon

	cmdDir = ''
	showCmd = win32con.SW_SHOWNORMAL #  win32con.SW_HIDE
	lpVerb = 'runas'  # causes UAC elevation prompt.

	# ShellExecute() doesn't seem to allow us to fetch the PID or handle
	# of the process, so we can't get anything useful from it. Therefore
	# the more complex ShellExecuteEx() must be used.

	procInfo = ShellExecuteEx(nShow=showCmd,
							  fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
							  lpVerb=lpVerb,
							  lpFile=cmd,
							  lpParameters=params)

	procHandle = procInfo['hProcess']   
	obj = win32event.WaitForSingleObject(procHandle, win32event.INFINITE)
	rc = win32process.GetExitCodeProcess(procHandle)

	if rc != 0:
		raise subprocess.CalledProcessError(rc, cmdLine)
	return rc
	
def check_call_as_admin(cmdLine=None):
	cmd = subprocess.list2cmdline([cmdLine[0]])
	params = subprocess.list2cmdline(cmdLine[1:])
	return run_as_admin(cmd, params)


def install_nullsoft_silent(path, extra_flags=()):
	check_call_as_admin([str(path), '/S', *extra_flags])


class cachedclassproperty(object):
	def __init__(self, func):
		self.__doc__ = getattr(func, '__doc__')
		self.func = func

	def __get__(self, obj, cls):
		value = self.func(cls)
		setattr(cls, self.func.__name__, value)
		return value

	def __repr__(self):
		cn = self.__class__.__name__
		return '<%s func=%s>' % (cn, self.func)

#asyncutils
@async_contextmanager      
async def http_request(session, verb, *args, **kwargs):
	#with async_timeout.timeout(timeout):
	headers = kwargs.get('headers', {})
	headers.setdefault('Accept-Language', 'en-US,en;q=0.5')
	headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0')
	headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
	
	kwargs['headers'] = headers
	
	logger.debug(f'headers={headers!r}')
	async with session.request(verb, *args, **kwargs) as response:
		yield response

'''		
async def chunked(response, chunk_size, timeout=60):
	while True:
		#with async_timeout.timeout(timeout):
		chunk = await response.content.read(chunk_size)
		if not chunk:
			break
		yield chunk
'''
		
def recurse_files(path):
	"""
	walks all files (not directories) in path and yields them one
	at a time (in arbitrary order) as paths relative to path
	"""
	for root, dirs, files in os.walk(str(path)):
		root_path = Path(root)
		for file in files:
			yield (root_path / file).relative_to(path)

def recurse_all(path):
	for root, dirs, files in os.walk(str(path)):
		root_path = Path(root)
		for d in dirs:
			yield root_path / d
		for file in files:
			yield root_path / file

async def extract_path_async(path, extractdir=None):
	_77PATH = r'C:\Program Files\7-Zip\7z.exe'
	
	extractdir = str(extractdir) or str(path.parent)
	#TODO add pbar?
	proc = await asyncio.create_subprocess_exec(
		str(_77PATH), 'x', '-y', str(path),
		cwd=extractdir,
	)
	stdout, stderr = await proc.communicate()
	if proc.returncode != 0:
		raise Exception(f'7zip returncode={proc.returncode}')