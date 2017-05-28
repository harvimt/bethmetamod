import cerberus
from game import Game
import os
from pprintpp import pprint as pp
from pathlib import Path
import yaml


class MyValidator(cerberus.Validator):
	def _validate_type_path(self, value):
		return isinstance(value, Path)

	def _normalize_coerce_path(self, value):
		return Path(value)

	def _normalize_default_setter_game_name(self, doc):
		return self.document_path[1]

	def _normalize_default_setter_profile_specific(self, doc, field):
		return Path(self.root_document['global'][field]) / self.document_path[1]


validator = MyValidator()

with open('config.yml') as f:
	config = yaml.safe_load(f)


def coercing_path(*, default):
	return {
		'type': 'path',
		'default_setter': default,
		'coerce': 'path',
		'required': False,
	}


schema = {
	'global': {
		'type': 'dict',
		'schema': {
			'base_dir': coercing_path(
				default=lambda doc: os.getcwd()),
			'downloads_dir': coercing_path(
				default=lambda doc: doc['base_dir']),
			'hashes_db_path': coercing_path(
				default=lambda doc: Path(doc['downloads_dir']) / 'hashes.shelve'),
			'mods_dir': coercing_path(
				default=lambda doc: Path(doc['base_dir']) / 'mods'),
			'logins_path': coercing_path(
				default=lambda doc: Path(doc['base_dir']) / 'logins.yml'),
			'vanilla_dir': coercing_path(
				default=lambda doc: Path(doc['base_dir']) / 'vanilla'),
			'purged_dir': coercing_path(
				default=lambda doc: Path(doc['base_dir']) / 'purged'),
		}
	},
	'profiles': {
		'required': False,
		'type': 'dict',
		'valueschema': {
			'type': 'dict',
			'default': {},
			'schema': {
				'game_name': {
					'type': 'string',
					'required': False,
					'default_setter': 'game_name',
					'coerce': str.casefold,
					'allowed': list(Game.games.keys()),
				},
				'downloads_db_path': coercing_path(
					default=lambda doc: Path(doc['downloads_dir']) / 'downloads.shelve'),
				**{
					k: {
						'type': 'path',
						'coerce': 'path',
						'required': False,
						'default_setter': 'profile_specific',
					}
					for k in ('mods_dir', 'downloads_dir', 'vanilla_dir', 'purged_dir')
				},
				'game': {
					'default_setter': lambda doc: Game.games[doc['game_name'].casefold()],
					'required': False,
				},
				'root_dir': {
					'type': 'path',
					'coerce': 'path',
					'required': False,
					'default_setter': lambda doc: doc['game'].root_dir,
				}
			}
		}
	}
}

if not validator.validate(config, schema):
	for e in validator._errors:
		pp(e.__dict__)
else:
	config = validator.normalized(config, schema)
