import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('bethmetamod')

import asyncio
import sys
from asyncio_extras.file import open_async
import os
import time
from enum import Enum
import json

from pathlib import Path
import io
import textwrap
from utils import get_regkey, cachedclassproperty, get_file_id, sha256_path, \
	http_request, extract_path_async, recurse_all, recurse_files, recurse_dirs, \
	dir_is_empty
import psutil
import aiohttp
import shelve
from collections import namedtuple
from boltons.cacheutils import cachedproperty
from boltons.strutils import camel2under
from boltons.fileutils import atomic_save
from tqdm import tqdm
import urllib.parse
import yaml
import re
from ntfsutils.hardlink import samefile, create as create_hardlink
import pefile
import known_folders

from datetime import datetime, timedelta
import shlex
import subprocess


class Game:
	"""Abstract base class representing a video game."""

	@classmethod
	def get_root_dir(cls, tries=5):
		try:
			return Path(get_regkey(r'HKLM', rf'SOFTWARE\WOW6432Node\Bethesda Softworks\{cls.REG_NAME}', 'installed path'))
		except FileNotFoundError:
			if tries:
				cls.ping_launcher()
				return cls.get_root_dir(tries=(tries - 1))
			else:
				raise

	@classmethod
	def ping_launcher(cls):
		"""Start the Launcher and then immediately close it."""
		cls.start_steam()
		for i in range(60):
			log.debug('waiting for 1 second')
			time.sleep(1)
			procs = map(psutil.Process, psutil.pids())
			ob_launcher, = (proc for proc in procs if proc.name() == cls.LAUNCHER_EXE)
			ob_launcher.kill()

	@classmethod
	def start_steam(cls):
		os.startfile(f'steam://run/{cls.STEAM_ID}')

	@cachedclassproperty
	def root_dir(cls):
		return cls.get_root_dir()

	@cachedclassproperty
	def game_exe(cls):
		return cls.root_dir / cls.GAME_EXE

	@cachedclassproperty
	def launcher_exe(cls):
		return cls.root_dir / cls.LAUNCHER_EXE

	@cachedclassproperty
	def tesxedit_exe(cls):
		return cls.root_dir / cls.TESXEDIT_EXE

	@cachedclassproperty
	def user_data_path(cls):
		# TODO probably more things I need to do to get localized "My Games"
		return Path(known_folders.get_path('Documents')) / 'My Games' / cls.REG_NAME

	@cachedclassproperty
	def app_data_path(cls):
		return Path(known_folders.get_path('LocalAppData')) / cls.REG_NAME

	@cachedclassproperty
	def user_ini(cls):
		return cls.user_data_path / f'{cls.REG_NAME}.ini'


class Oblivion(Game):
	REG_NAME = 'oblivion'
	BOSS_NAME = 'Oblivion'
	STEAM_ID = '22330'
	LAUNCHER_EXE = 'OblivionLauncher.exe'
	GAME_EXE = 'Oblivion.exe'
	TESXEDIT_EXE = 'TES4Edit.exe'
	NEXUS_NAME = 'oblivion'
	DEFAULT_ARCHIVE_LIST = 'Oblivion - Meshes.bsa, Oblivion - Textures - Compressed.bsa, Oblivion - Sounds.bsa, Oblivion - Voices1.bsa, Oblivion - Voices2.bsa, Oblivion - Misc.bsa'


class Config:
	DOWNLOADS_DIR = Path(r'W:\bethmetamod-dls')  # TODO
	DOWNLOADS_DB = Path(r'W:\bethmetamod-dls\downloads.shelve')
	HASHES_DB = Path(r'W:\bethmetamod-dls\hashes.shelve')
	MODS_DIR = Path(r'M:\bethmetamod\mods')
	LOGIN_PATH = Path(r'M:\bethmetamod\logins.yml')
	VANILLA_DIR = Path(r'M:\bethmetamod\vanilla')
	PURGED_DIR = Path(r'M:\bethmetamod\purged')
	CHUNK_SIZE = (1024**2)  # 1 MB

	@cachedclassproperty
	def game(cls):
		return Oblivion

	@cachedclassproperty
	def downloads_db(cls):
		return shelve.open(str(cls.DOWNLOADS_DB))

	@cachedclassproperty
	def hashes_db(cls):
		return shelve.open(str(cls.HASHES_DB))

	@cachedclassproperty
	def login_info(cls):
		with cls.LOGIN_PATH.open('r') as f:
			return yaml.safe_load(f)

	@cachedclassproperty
	def mod_ownership_path(cls):
		return cls.MODS_DIR / 'mod_ownership.json'


DownloadInfo = namedtuple('DownloadInfo', ('filename', 'size', 'sha256'))


class BaseDownload:
	def __init__(self):
		self.__dl_info = None

	@property
	def dl_info(self):
		if self.__dl_info is None:
			try:
				self.__dl_info = Config.downloads_db[self.dl_id]
			except KeyError:
				self.__dl_info = None
		return self.__dl_info

	@dl_info.setter
	def dl_info(self, value):
		self.__dl_info = Config.downloads_db[self.dl_id] = value

	async def extract(self, mod):
		dl_path = mod.dl_path / self.dl_info.filename
		await extract_path_async(dl_path, mod.mod_path)

	async def _predownload(self, mod, session, force):
		"""Return True if download is necessary."""
		if self.dl_info is None:
			log.debug("must download this file, we don't even know it's filename!")
			return True
		dl_path = mod.dl_path / self.dl_info.filename
		log.debug(f'checking to see if {dl_path} needs to be downloaded')
		do_download = True
		if not dl_path.exists():
			log.debug('does not exist must download')
		elif Config.hashes_db.get(self.dl_info.sha256) == get_file_id(dl_path):
			log.debug('file_id matches cached version, skipping download')
			do_download = False
		elif self.dl_info.sha256 == sha256_path(dl_path):
			log.debug('sha256 hash matches despite file_id failing, skipping download')
			Config.hashes_db[self.dl_info.sha256] = get_file_id(dl_path)
			do_download = False

		if not do_download:
			if force:
				log.info(f'Forcing download that would not have happened except force=True')
			else:
				log.info(f'{dl_path} already exists and passes hash check, skipping download')
				return False

		return True

	async def _do_download(self, url, mod, session, **kwargs):
		log.info(f'Downloading {url}')
		async with http_request(session, 'get', url, timeout=None, **kwargs) as response:
			response.raise_for_status()
			if self.dl_info is not None:
				dl_filename = self.dl_info.filename
				dl_size = self.dl_info.size
			else:
				try:
					dispo = response.headers['Content-Disposition']
					_, dl_filename = dispo.split('filename=')
					if dl_filename.startswith(('"', "'")):
						dl_filename = dl_filename[1:-1]
				except:
					*_, dl_filename = urllib.parse.unquote(urllib.parse.urlparse(url).path).split('/')

				try:
					dl_size = int(response.headers.get('Content-Length'))
				except (ValueError, TypeError):
					dl_size = None

			dl_path = mod.dl_path / dl_filename

			log.info(f'Saving content to {dl_path}')
			log.info(f'Content size: {dl_size}')
			log.debug(f'headers: {response.headers!r}')
			pbar = tqdm(total=dl_size, unit='B', unit_scale=True, desc=dl_filename)
			dl_path.parent.mkdir(parents=True, exist_ok=True)
			async with open_async(str(dl_path), 'wb') as f:
				async for chunk in response.content.iter_chunked(Config.CHUNK_SIZE):
					await f.write(chunk)
					pbar.update(len(chunk))
			pbar.close()

			if b'ERROR 403: Forbidden' in dl_path.open('rb').read(1024 * 8):
				dl_path.unlink()
				raise Exception("Nexus Doesn't Like us :-(")

			self.dl_info = DownloadInfo(
				filename=dl_filename,
				sha256=sha256_path(dl_path),
				size=dl_path.stat().st_size,
			)
			Config.hashes_db[self.dl_info.sha256] = get_file_id(dl_path)


class NexusDownload(BaseDownload):
	cookies = None
	logged_in_at = None
	redirect_re = re.compile(r'(?ms).*?window\.location\.href = "(http://filedelivery\.nexusmods\.com[^"]*?)".*')
	creds_cache_time = timedelta(hours=1)

	@cachedclassproperty
	def login_url(cls):
		return f'https://www.nexusmods.com/{Config.game.NEXUS_NAME}/sessions/?Login'

	def __init__(self, nexus_id, game_name=None):
		self.nexus_id = nexus_id
		self.game_name = game_name or Config.game.NEXUS_NAME

		self.dl_id = '\t'.join((type(self).__name__, self.game_name, self.nexus_id))
		super().__init__()

	@classmethod
	async def login(cls, session):
		log.debug('NexusDownload.login called')

		# if cls.cookies is not None and cls.logged_in_at is not None and (datetime.now() - cls.logged_in_at) < cls.creds_cache_time:
		#    log.info('Already logged in.')
		#    session.cookie_jar.update_cookies(cls.cookies)
		#    return
		log.info('Logging into nexusmods.com')

		async with http_request(session, 'post', cls.login_url, data=Config.login_info['nexus']) as response:
			response.raise_for_status()

		cls.logged_in_at = datetime.now()
		cls.cookies = dict(session.cookie_jar._cookies)

	async def download(self, mod, session, force=False):
		if not await self._predownload(mod, session, force):
			return

		# nexus specific
		await self.login(session)
		url = f'http://www.nexusmods.com/{self.game_name}/ajax/downloadfile?id={self.nexus_id}&rrf'

		async with http_request(session, 'get', url) as response:
			response.raise_for_status()
			page_text = await response.text()
			new_url = self.redirect_re.match(page_text).group(1)

		await self._do_download(new_url, mod, session, headers={'Referer': url})


class Download(BaseDownload):
	def __init__(self, url, **kwargs):
		self.url = url
		self.kwargs = kwargs
		self.dl_id = '\t'.join((type(self).__name__, url))
		super().__init__()

	async def download(self, mod, session, force=False):
		if not await self._predownload(mod, session, force):
			return

		await self._do_download(self.url, mod, session)


class PathType(Enum):
	PLUGIN = '.esp or .esm script file'
	BSA_ARCHIVE = '.bsa archive file'
	OBSE_PLUGIN = 'OBSE Plugin'
	EXECUTABLE = '.exe or .dll that is not something else'
	TEXTURE = 'textures and other images'
	MODEL = '3D Model'

	INSTALLER_METADATA = 'installer metadata like omod converstion data or wizard scripts'
	MENU_XML = 'Menu xml file (scalaform).'

	DOCUMENTATION = 'READMEs and other docs'
	CONFIGURATION = 'Configuration files'

	OTHER = 'other'


def classify_path(path):
	"""
	takes in a path relative to the game directory (not the Data/ directory).
	and tells what type it is.

	returns a PathType enumeration.
	"""
	#TODO lookup how to handle path-likes
	path_parts = list(map(str.lower, path.parts))
	path_suffix = path.suffix.lower()
	suffix_map = {
		'.esp': PathType.PLUGIN,
		'.esm': PathType.PLUGIN,
		'.bsa': PathType.BSA_ARCHIVE,
		'.exe': PathType.EXECUTABLE,
		'.bat': PathType.EXECUTABLE,
		'.dds': PathType.TEXTURE,
		'.html': PathType.DOCUMENTATION,
		'.txt': PathType.DOCUMENTATION,
		'.rtf': PathType.DOCUMENTATION,
		'.ini': PathType.CONFIGURATION,
		'.cfg': PathType.CONFIGURATION,
	}
	suffix_map_secondary = {
		'.jpg': PathType.TEXTURE,
		'.jpeg': PathType.TEXTURE,
		'.png': PathType.TEXTURE,
	}
	if path_suffix in suffix_map:
		return suffix_map[path_suffix]
	elif path_suffix == '.dll':
		if path_parts[:3] == ('data', 'obse', 'plugins'):
			return PathType.OBSE_PLUGIN
		else:
			return PathType.EXECUTABLE
	elif path_suffix == '.xml':
		if path_parts[:2] == ('data', 'menus'):
			return PathType.MENU_XML
		else:
			return PathType.CONFIGURATION
	elif 'readme' in path.name.lower():
		return PathType.DOCUMENTATION
	elif 'docs' in path_parts:
		return PathType.DOCUMENTATION
	elif path_suffix in suffix_map_secondary:
		return suffix_map_secondary[path_suffix]
	else:
		return PathType.OTHER


class Mod:
	downloads = ()

	@cachedclassproperty
	def mod_name(cls):
		return camel2under(cls.__name__)

	@cachedproperty
	def mod_path(self):
		return Config.MODS_DIR / self.mod_name

	@cachedproperty
	def dl_path(self):
		return Config.DOWNLOADS_DIR / self.mod_name

	async def download(self, session):
		for download in self.downloads:
			await download.download(self, session)

	def EditINI(self, section, key_name, value, ini_path=None):
		# copying OBMM/TMM's naming convention since it's used in all the install scripts
		ini_path = ini_path or Config.game.user_ini

		new_lines = []
		in_section = False
		value_written = False
		for line in ini_path.read_text().splitlines():
			if line.strip() == section:
				in_section = True
			elif in_section:
				if line.startswith('['):
					in_section = False
					if not value_written:
						new_lines.append(f'{key_name}={value}')
				elif line.split('=', 1)[0].strip() == key_name:
					if not value_written:
						new_lines.append(f'{key_name}={value}')
						value_written = True
					continue
			new_lines.append(line)

		ini_path.write_text('\n'.join(new_lines))

	def GetINI(self, section, key_name, ini_path=None):
		# copying OBMM/TMM's naming convention since it's used in all the install scripts
		value = None
		ini_path = ini_path or Config.game.user_ini

		in_section = False
		for line in ini_path.read_text().splitlines():
			if line.strip() == section:
				in_section = True
			elif in_section:
				if line.startswith('['):
					in_section = False
				elif line.split('=', 1)[0].strip() == key_name:
					value = line.split('=', 1)[1].strip()
		return value

	async def preprocess(self):
		"""extracting from archives, binary patching vanilla files."""
		pass

	async def extract(self, force=False):
		self.mod_path.mkdir(exist_ok=True, parents=True)
		if not force:
			try:
				next(self.mod_path.iterdir())
			except StopIteration:
				pass
			else:
				log.info(f'{self.mod_path} is not empty, extracted before, skipping extraction')
				return  # mod dir not empty
		for download in self.downloads:
			await download.extract(self)

	def modify(self):
		"""
		Yield a tuple of (source path, dest_path) where source_path is an
		absolute path and dest_path is an path relative to game.root_dir
		"""
		# find data dir
		candidates = set()

		for path in recurse_all(self.mod_path):
			if path.is_dir():
				if path.name.lower() == 'data':
					candidates.add(path)
				elif path.name.lower() in ('textures', 'music', 'video', 'shaders', 'obse'):
					candidates.add(path.parent)
			elif path.suffix.lower() in {'.bsa', '.esp', '.esm'}:
				candidates.add(path.parent)

		if len(candidates) != 1:
			raise Exception(f'should be exactly 1 candidate path but there are more/less: they are: {candidates}')

		root_path, = candidates

		for path in recurse_files(root_path):
			if path.parts[0].lower() == 'omod conversion data':
				continue
			yield root_path / path, Path('./data') / path

	async def postprocess(self):
		"""Edit ini files, I/O unintensive stuff that must be performed after modify."""
		pass

	def install(self, sub_path, root_path=None, prefix='Data/'):
		# TODO bad name
		root_path = root_path or self.mod_path

		for path in recurse_files(root_path / sub_path):
			src_path = root_path / sub_path / path
			dest_path = Path(prefix) / sub_path / path
			if map(str.lower, dest_path.parts[0:1]) == ('data', 'omod conversion data'):
				continue
			yield src_path, dest_path


class OBSE(Mod):
	downloads = [
		Download('http://obse.silverlock.org/download/obse_0021.zip'),
		Download('http://obse.silverlock.org/download/obse_loader.zip'),
	]

	def modify(self):
		for path in recurse_files(self.mod_path):
			if path.parts[0] == 'src':
				continue
			yield self.mod_path / path, path


class FarCryGrass(Mod):
	downloads = [NexusDownload('1000014269')]


class OBSETester(Mod):
	# requires OBSE
	downloads = [NexusDownload('65277')]


class OneTweak(Mod):
	downloads = [NexusDownload('1000231728', game_name='skyrim')]

	def modify(self):
		for path in self.mod_path.glob(r'*/SKSE/plugins/*'):
			yield path, Path('./Data/OBSE/plugins') / path.name


class MoreHeap(Mod):
	downloads = [NexusDownload('1000006402')]

	def modify(self):
		yield self.mod_path / 'Version.dll', Path('Version.dll')


class ENB(Mod):
	downloads = [
		Download(
			'http://enbdev.com/enbseries_oblivion_v0181.zip',
			headers={'referer': 'http://enbdev.com/mod_tesoblivion_v0181.htm'},
		)
	]

	def modify(self):
		for path in self.mod_path.glob('WrapperVersion/*'):
			yield path, Path('.') / path.name


class ENBoost(Mod):
	# requires ENB
	downloads = [NexusDownload('1000007218')]

	def __init__(self, gpu=None, os=None):
		if gpu is None:
			lines = subprocess.check_output('wmic path win32_videocontroller get /format:list').decode('utf8').splitlines()
			pairs = (s.split('=', 1) for s in lines if '=' in s)
			adapters = {v for k, v in pairs if k == 'AdapterCompatibility'}

			nvidia_present = 'NVIDIA' in adapters
			amd_present = 'AMD' in adapters

			assert nvidia_present or amd_present
			if nvidia_present:
				gpu = 'NVidia'
			elif amd_present:
				gpu = 'AMD'
			else:
				raise Exception('Unsupported gpu manufacturer')

			log.info(f'autodetected gpu manufacturer: {gpu}')

		if os is None:
			import platform
			os = f'{platform.architecture()[0]}OS'
			log.info(f'autodetected os architecture: {os}')

		assert gpu in {'NVidia', 'AMD'}
		assert os in {'64bitOS', '32bitOS'}
		self.gpu = gpu
		self.os = os

	def modify(self):
		yield (self.mod_path / self.gpu / self.os / 'enblocal.ini'), Path('enblocal.ini')


class FourGBPatch(Mod):
	async def preprocess(self):
		old_path = Config.VANILLA_DIR / Config.game.GAME_EXE
		new_path = self.mod_path / Config.game.GAME_EXE
		if new_path.exists():
			return
		pe = pefile.PE(str(old_path))
		pe.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE = True
		pe.write(filename=str(new_path))
		pe.close()
		del pe

	def modify(self):
		yield self.mod_path / Config.game.GAME_EXE, Path('.') / Config.game.GAME_EXE


class ConScribe(Mod):
	downloads = [NexusDownload('1000001455')]


class Pluggy(Mod):
	downloads = [NexusDownload('72172')]

	def modify(self):
		yield self.mod_path / 'OBSE_Elys_Pluggy.dll', Path('Data/OBSE/Plugins/OBSE_Elys_Pluggy.dll')
		yield self.mod_path / 'OBSE_Elys_Pluggy.dlx', Path('Data/OBSE/Plugins/OBSE_Elys_Pluggy.dlx')


class DarnifiedUI(Mod):
	downloads = [NexusDownload('34632')]

	def __init__(
		self, *,
		player_name='player',
		custom_font_1='Default', classic_inventory=False, install_docs=False,
		colored_local_map=False, no_quest_added_popup=False, font_size='Normal',
	):

		assert custom_font_1 in {
			"Default",
			"!Sketchy_Times_36",
			"Dundalk_28",
			"Endor_20",
			"FantaisieArtistique_28",
			"Immortal_28",
			"Kingthings_Exeter_28",
			"Knights_Quest_36",
			"Morris_Roman_28",
			"Ringbearer_22",
			"Roosevelt_28",
			"Walshes_36",
			"Yataghan_24",
			"Kingthings_Calligraphica_36",
			"LaBrit_28",
			"Gushing_Meadow_28",
		}

		assert font_size in {"Normal", "Large"}

		assert isinstance(player_name, str)
		assert isinstance(classic_inventory, bool)
		assert isinstance(install_docs, bool)
		assert isinstance(colored_local_map, bool)
		assert isinstance(no_quest_added_popup, bool)

		self.player_name = player_name
		self.custom_font_1 = custom_font_1
		self.classic_inventory = classic_inventory
		self.install_docs = install_docs
		self.colored_local_map = colored_local_map
		self.no_quest_added_popup = no_quest_added_popup
		self.font_size = font_size

	def modify(self):
		yield from self.install(Path('./textures'))
		yield from self.install(Path('./fonts'))

		yield from self.install(Path('./meshes'))
		yield from self.install(Path('./menus'))

		'''
		FIXME If Oblivion XP don't replace these files
			sf.CancelDataFileCopy("menus\\main\\stats_menu.xml");
			sf.CancelDataFileCopy("menus\\prefabs\\darn\\stats_config.xml");
			sf.CancelDataFileCopy("menus\\levelup_menu.xml");
		}
		'''
		if self.player_name:
			xml = (self.mod_path / "menus/options/credits_menu.xml").read_text().replace("<string>You</string>", f"<string>{self.player_name}</string>")
			(self.mod_path / "menus/options/credits_menu_customized.xml").write_text(xml)
			yield self.mod_path / "menus/options/credits_menu_customized.xml", Path("menus/options/credits_menu.xml")

		if self.classic_inventory:
			yield from self.install(Path('./menus'), self.mod_path / 'custom_files/classic_inventory')

		if self.install_docs:
			yield from self.install(Path('Docs'))

		if self.no_quest_added_popup:
			yield self.mod_path / "custom_files/empty.xml", Path("menus/generic/quest_added.xml")

		if self.custom_font_1 != "Default":
			yield self.mod_path / f"custom_files/fonts/DarN_{self.custom_font_1}.fnt", "Fonts\\DarN_{self.custom_font_1}.fnt"
			yield self.mod_path / f"custom_files/fonts/DarN_{self.custom_font_1}.tex", "Fonts\\DarN_{self.custom_font_1}.tex"

		if False:  # FIXME if Trollf Loading Screens are installed
			yield self.mod_path / "custom_files/trollf_loading_menu.xml", Path('menus/loading_menu.xml')

		kcas = True   # FIXME make automatic; running Realistic Levelling
		obxp = False  # FIXME make automatic; not running oblivion XP
		if kcas and not obxp:  # FIXME if "KCAS-AF Menus" are installed
			xml = (self.mod_path / "menus/prefabs/darn/stats_config.xml").read_text().replace("<_KCAS> &false; </_KCAS>", "<_KCAS> &true; </_KCAS>")
			(self.mod_path / "menus/prefabs/darn/stats_config_kcas.xml").write_text(xml)
			yield self.mod_path / "menus/prefabs/darn/stats_config_kcas.xml", Path("menus/prefabs/darn/stats_config.xml")
			yield self.mod_path / "custom_files/KCAS_levelup_menu.xml", Path("menus/levelup_menu.xml")

	async def postprocess(self):
		if self.colored_local_map:
			self.EditINI("[Display]", "bLocalMapShader", "0")
			self.EditINI("[Fonts]", "SFontFile_1", f"Data\\Fonts\\DarN_{self.custom_font_1}.fnt")

		self.EditINI("[Fonts]", "SFontFile_4", "Data\\Fonts\\DarN_Oblivion_28.fnt")

		if self.font_size == "Large":
			self.EditINI("[Fonts]", "SFontFile_2", "Data\\Fonts\\DarN_LG_Kingthings_Petrock_14.fnt")
			self.EditINI("[Fonts]", "SFontFile_3", "Data\\Fonts\\DarN_LG_Kingthings_Petrock_18.fnt")
		else:
			self.EditINI("[Fonts]", "SFontFile_2", "Data\\Fonts\\DarN_Kingthings_Petrock_14.fnt")
			self.EditINI("[Fonts]", "SFontFile_3", "Data\\Fonts\\DarN_Kingthings_Petrock_16.fnt")

		self.EditINI("[Fonts]", "SFontFile_5", "Data\\Fonts\\Handwritten.fnt")


class DarnifiedUIConfigAddon(Mod):
	downloads = [NexusDownload('71200')]


class ArchiveInvalidationInvalidated(Mod):
	downloads = [NexusDownload('9933')]

	async def postprocess(self):
		archive_list = self.GetINI('[Archive]', 'SArchiveList') or Config.game.DEFAULT_ARCHIVE_LIST
		archive_list = list(map(str.strip, archive_list.split(',')))
		if archive_list[1] != 'ArchiveInvalidationInvalidated!.bsa':
			archive_list = [a for a in archive_list if a != 'ArchiveInvalidationInvalidated!.bsa']
			archive_list.insert(1, 'ArchiveInvalidationInvalidated!.bsa')
			self.EditINI('[Archive]', 'SArchiveList', ', '.join(archive_list))


class INITweaks(Mod):
	async def postprocess(self):
		self.EditINI('[General]', 'SIntroSequence', '')

	def modify(self):
		return (x for x in ())  # empty generator


class FastExit(Mod):
	downloads = [NexusDownload('37416')]


class Streamline(Mod):
	downloads = [NexusDownload('9940')]


class MenuQue(Mod):
	downloads = [NexusDownload('1000003136')]


class OblivionStutterRemover(Mod):
	downloads = [NexusDownload('1000006913'), NexusDownload('75837')]

	def modify(self):
		yield from self.install(Path('./Data'), prefix=Path('.'))

		for dll_path in self.mod_path.glob('*.dll'):
			yield dll_path, Path('./Data/OBSE/Plugins/ComponentDLLs') / dll_path.name


OSR = OblivionStutterRemover


class QuarlsTexturePack3Redimized(Mod):
	downloads = [NexusDownload('1000008539')]


QTP3R = QuarlsTexturePack3Redimized


class GraphicImprovementProject(Mod):
	downloads = [NexusDownload('1000016139')]


class ZiraHorseCompilationModpack(Mod):
	downloads = [NexusDownload('77575')]


class RingRetexture(Mod):
	downloads = [NexusDownload('1000016754')]


class KafeisArmoredCirclets(Mod):
	downloads = [NexusDownload('9492')]


class KoldornsSewerTextures2(Mod):
	downloads = [NexusDownload('31103')]


class KoldornsCaveTextures2(Mod):
	downloads = [NexusDownload('31015')]


class ManglersEquipmentAndAmmoTextures(Mod):
	downloads = [NexusDownload('1000004718')]


MEAT = ManglersEquipmentAndAmmoTextures


class BomretTexturePackForShiveringIslesWithUSIP(Mod):
	downloads = [NexusDownload('1000010426')]


'''
Astrob0y's Tweaked ENB
http://www.nexusmods.com/oblivion/ajax/downloadfile?id=1000008935
'''

# Gameplay


class RealisticLeveling(Mod):
	downloads = [NexusDownload('85564')]
	# TODO - handle ini setting


class HUDStatusBars(Mod):
	downloads = [NexusDownload('86447')]

	def modify(self):
		yield from self.install(Path(), self.mod_path / Path('00 Core'))
		yield from self.install(Path(), self.mod_path / Path('01 Vanilla style'))


class UnnecessaryViolenceIII(Mod):
	downloads = [NexusDownload('1000011789')]

	def modify(self):
		for src, dest in super().modify():
			if dest.parent == Path('Data/ini/optional uv3 hsb'):
				continue
			yield src, dest

		yield from self.install(Path('.'), self.mod_path / 'ini/optional uv3 hsb', prefix=Path('Data/ini'))


UV3 = UnnecessaryViolenceIII


class NifSE(Mod):
	downloads = [NexusDownload('84943')]


class ATakeAllAlsoBooks(Mod):
	downloads = [NexusDownload('51876')]


class HarvestFlora(Mod):
	downloads = [NexusDownload('21250')]

	def __init__(self, *, no_mushroom_stalks=False):
		self.no_mushroom_stalks = no_mushroom_stalks

	#def modify(self):
		#pass


class HarvestContainers(Mod):
	downloads = [NexusDownload('62787')]

	def __init__(
		self, *,
		ore_nodes=False,
		player_home_addon=False,
		havok_crates_addon=False,
		flat_top_barrels=False,
		si_ore_nodes=False,
	):
		self.ore_nodes = ore_nodes
		self.player_home_addon = player_home_addon
		self.havok_crates_addon = havok_crates_addon
		self.flat_top_barrels = flat_top_barrels

	def modify(self):
		yield self.mod_path / 'Harvest Containers v0.99.14/Harvest[Containers].esm', Path('./Data/Harvest[Containers].esm')
		self.install(Path('.'), self.mod_path / 'Harvest Containers v0.99.14/Standalones/Vanilla')

		if True:  # FIXME SI is installed
			self.install(Path('.'), self.mod_path / 'Harvest Containers v0.99.14/Standalones/Shivering Isles')

		# TODO handle addons


if sys.platform == 'win32':
	loop = asyncio.ProactorEventLoop()
	asyncio.set_event_loop(loop)
else:
	loop = asyncio.get_event_loop()


async def main(loop):
	mod_list = [
		# Install outside of Data/
		FastExit(),
		FourGBPatch(),
		OBSE(),
		ENB(),
		ENBoost(),
		MoreHeap(),
		# OBSE Plugins
		OneTweak(),
		# OBSETester(),
		MenuQue(),
		ConScribe(),
		Pluggy(),
		NifSE(),
		# Performance
		Streamline(),
		OSR(),
		# Necessary Tweaks
		ATakeAllAlsoBooks(),
		DarnifiedUI(),
		DarnifiedUIConfigAddon(),
		HarvestFlora(),
		HarvestContainers(),
		# Textures
		QTP3R(),
		GraphicImprovementProject(),
		ZiraHorseCompilationModpack(),
		RingRetexture(),
		KafeisArmoredCirclets(),
		KoldornsSewerTextures2(),
		KoldornsCaveTextures2(),
		MEAT(),
		BomretTexturePackForShiveringIslesWithUSIP(),
		# Gameplay
		RealisticLeveling(),
		HUDStatusBars(),
		UV3(),
		# Install Last
		INITweaks(),
		ArchiveInvalidationInvalidated(),
	]
	converged_paths = {}
	path_mod_owner = {}  # which mod owns which path
	for path in recurse_files(Config.VANILLA_DIR):
		converged_paths[str(path).lower()] = Config.VANILLA_DIR / path

	log.info('downloading')
	for mod in mod_list:
		async with aiohttp.ClientSession(loop=loop) as session:
			await mod.download(session)

	if False:  # stop after download?
		log.info('stopping after download')
		return

	log.info('extracting')
	for mod in mod_list:
		await mod.extract()

	if False:  # stop after extract?
		log.info('stopping after extract')
		return

	log.info('pre-processing')
	for mod in mod_list:
		await mod.preprocess()

	log.info('calulcating convergance for each mod')
	for mod in mod_list:
		log.info(f'converging {mod.mod_name}')
		for source_path, dest_path in mod.modify():
			if dest_path.is_absolute():
				raise Exception(f'{source_path} is not absolute')
			if not source_path.is_absolute():
				raise Exception(f'{source_path} is not absolute')
			elif not source_path.exists():
				raise Exception(f'{source_path} does not exist, bad modify code')
			elif not source_path.is_file():
				raise Exception(f'{source_path} is not a regular file.')

			converged_paths[str(dest_path).lower()] = source_path
			path_mod_owner[str(dest_path).lower()] = mod.mod_name

	log.info('applying convergance')
	for dest_path, source_path in converged_paths.items():
		dest_path = Config.game.root_dir / dest_path
		if not dest_path.exists() or not samefile(str(dest_path), str(source_path)):
			if dest_path.exists():
				dest_path.unlink()  # FIXME move to purged dir?
			dest_path.parent.mkdir(exist_ok=True, parents=True)
			try:
				create_hardlink(str(source_path), str(dest_path))
			except FileNotFoundError:
				raise Exception(f'failed to hard link {source_path} to {dest_path} {source_path} (or {dest_path.parent}) not found')

	log.info('purging')
	try:
		with Config.mod_ownership_path.open('rb') as f:
			old_path_mod_owner = json.load(f)
	except FileNotFoundError:
		old_path_mod_owner = {}
	purged_root = Config.PURGED_DIR / datetime.now().isoformat().replace(':', '')
	for path in recurse_files(Config.game.root_dir):

		if (
			str(path).lower() not in converged_paths and
			not path.suffix.lower() in {'.ini', '.cfg', '.json', '.log'} and
			#TODO don't purge xml files unless they're menu files
			not path.parts[0].lower() in {'obmm', 'mopy'}
		):
			if str(path).lower() in old_path_mod_owner:
				path.unlink()
			else:
				purged_path = purged_root / path
				purged_path.parent.mkdir(exist_ok=True, parents=True)
				(Config.game.root_dir / path).rename(purged_path)

	log.info('purging empty directories')
	for d in recurse_dirs(Config.game.root_dir):
		if dir_is_empty(d):
			d.rmdir()

	log.info('postprocessing')
	for mod in mod_list:
		await mod.postprocess()
	log.info('Done Applying Changes')

	log.info('modifying load order')
	boss_uninstall_string = get_regkey('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BOSS', 'UninstallString')
	boss_install_location = Path(shlex.split(boss_uninstall_string)[0]).parent
	boss_exe_path = boss_install_location / 'boss.exe'

	proc = await asyncio.create_subprocess_exec(
		str(boss_exe_path), '-s', '-g', Config.game.BOSS_NAME,
		cwd=str(boss_install_location),
		stderr=sys.stderr,
		stdout=sys.stdout,
	)
	await proc.wait()

	log.info('enabling all .esp and .esm files')
	PLUGINS_HEADER = textwrap.dedent('''
	# This file is used to tell Oblivion which data files to load.
	# WRITE YOUR OWN PYTHON SCRIPT TO MODIFY THIS FILE (lol)
	# Please do not modify this file by hand.
	''').strip()

	with atomic_save(str(Config.game.app_data_path / 'plugins.txt')) as f:
		with io.TextIOWrapper(f, 'ascii') as ef:
			ef.write(PLUGINS_HEADER)
			ef.write('\n')
			for esm in Config.game.root_dir.glob('Data/*.esm'):
				ef.write(esm.name)
				ef.write('\n')
			for esp in Config.game.root_dir.glob('Data/*.esp'):
				ef.write(esp.name)
				ef.write('\n')

	log.info('saving which mod owns which file')
	with atomic_save(str(Config.mod_ownership_path)) as f:
		json.dump(path_mod_owner, f)


if __name__ == '__main__':
	loop.run_until_complete(main(loop))
