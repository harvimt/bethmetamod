import logging
log = logging.getLogger(__name__)
from utils import cachedclassproperty, get_regkey
from pathlib import Path
import time
import known_folders
import psutil
import os


class Game:
	"""Abstract base class representing a video game."""
	games = {}

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

	@cachedclassproperty
	def REG_NAME(cls):
		return cls.__name__

	@cachedclassproperty
	def BOSS_NAME(cls):
		return cls.__name__

	@cachedclassproperty
	def LAUNCHER_EXE(cls):
		return f'{cls.__name__}Launcher.exe'

	@cachedclassproperty
	def GAME_EXE(cls):
		return f'{cls.__name__}.exe'

	@cachedclassproperty
	def NEXUS_NAME(cls):
		return cls.__name__.lower()

	def __init_subclass__(cls, **kwargs):
		super().__init_subclass__(**kwargs)
		cls.games[cls.__name__.casefold()] = cls


class Oblivion(Game):
	STEAM_ID = '22330'
	TESXEDIT_EXE = 'TES4Edit.exe'
	NEXUS_NAME = 'oblivion'
	DEFAULT_ARCHIVE_LIST = 'Oblivion - Meshes.bsa, Oblivion - Textures - Compressed.bsa, Oblivion - Sounds.bsa, Oblivion - Voices1.bsa, Oblivion - Voices2.bsa, Oblivion - Misc.bsa'


class FalloutNV(Game):
	STEAM_ID = '22380'
	TESXEDIT_EXE = 'FNVEdit.exe'
	NEXUS_NAME = 'newvegas'
	DEFAULT_ARCHIVE_LIST = 'Fallout - Textures.bsa, Fallout - Textures2.bsa, Fallout - Meshes.bsa, Fallout - Voices1.bsa, Fallout - Sound.bsa,  Fallout - Misc.bsa'
