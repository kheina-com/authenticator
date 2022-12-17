from hashlib import sha3_512
from math import ceil, floor
from re import IGNORECASE
from re import compile as re_compile
from secrets import randbelow
from time import time
from typing import Any, Dict
from uuid import UUID, uuid4

import ujson as json
from argon2 import PasswordHasher as Argon2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kh_common import logging
from kh_common.auth import Scope
from kh_common.base64 import b64encode
from kh_common.caching.key_value_store import KeyValueStore
from kh_common.config.credentials import argon2, secrets
from kh_common.datetime import datetime
from kh_common.exceptions.http_error import BadRequest, Conflict, HttpError, InternalServerError, NotFound, Unauthorized
from kh_common.hashing import Hashable
from kh_common.models.auth import AuthState, TokenMetadata
from kh_common.sql import SqlInterface
from psycopg2.errors import UniqueViolation

from models import AuthAlgorithm


"""
table definition:
CREATE TABLE kheina.auth.token_keys (
	key_id INT UNIQUE GENERATED ALWAYS AS IDENTITY,
	algorithm TEXT NOT NULL,
	public_key BYTEA NOT NULL,
	signature BYTEA NOT NULL,
	issued TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires TIMESTAMPTZ NOT NULL DEFAULT current_date + interval '30 days',
	PRIMARY KEY (algorithm, key_id)
);
CREATE INDEX token_keys_algorithm_issued_expires_joint_index ON kheina.auth.token_keys (algorithm, issued, expires);
"""


KVS: KeyValueStore = KeyValueStore('kheina', 'token')


class Authenticator(SqlInterface, Hashable) :

	EmailRegex = re_compile(r'^(?P<user>[A-Z0-9._%+-]+)@(?P<domain>[A-Z0-9.-]+\.[A-Z]{2,})$', flags=IGNORECASE)

	def __init__(self) :
		Hashable.__init__(self)
		SqlInterface.__init__(self)
		self.logger = logging.getLogger('auth')
		self._initArgon2()
		self._key_refresh_interval = 60 * 60 * 24  # 24 hours
		self._token_expires_interval = 60 * 60 * 24 * 30  # 30 days
		self._token_version = '1'
		self._token_algorithm = AuthAlgorithm.ed25519.name
		self._public_keyring = { }
		self._active_private_key = {
			'key': None,
			'algorithm': None,
			'issued': 0,
			'start': 0,
			'end': 0,
			'id': 0,
		}


	def _validateEmail(self, email: str) -> Dict[str, str] :
		email = Authenticator.EmailRegex.search(email)
		if not email :
			raise BadRequest('the given email is invalid.')
		return email.groupdict()


	def _initArgon2(self) :
		self._argon2 = Argon2(**argon2)
		self._secrets = [bytes.fromhex(salt) for salt in secrets]


	def _hash_email(self, email) :
		# always use the first secret since we can't retrieve the record without hashing it
		return sha3_512(email.encode() + self._secrets[0]).digest()


	def _calc_timestamp(self, timestamp) :
		return int(self._key_refresh_interval * floor(timestamp / self._key_refresh_interval))


	def generate_token(self, user_id: int, token_data: dict) :
		issued = time()
		expires = self._calc_timestamp(issued) + self._token_expires_interval

		if self._active_private_key['start'] <= issued < self._active_private_key['end'] :
			private_key = self._active_private_key['key']
			pk_issued = self._active_private_key['issued']
			key_id = self._active_private_key['id']

		else :
			# initialize a new private key
			start = self._calc_timestamp(issued)
			end = start + self._key_refresh_interval
			self._active_private_key = {
				'key': None,
				'algorithm': self._token_algorithm,
				'issued': 0,
				'start': start,
				'end': end,
				'id': 0,
			}

			private_key = self._active_private_key['key'] = Ed25519PrivateKey.generate()
			public_key = private_key.public_key().public_bytes(
				encoding=serialization.Encoding.DER,
				format=serialization.PublicFormat.SubjectPublicKeyInfo,
			)
			signature = private_key.sign(public_key)

			# insert the new key into db
			data = self.query("""
				INSERT INTO kheina.auth.token_keys
				(public_key, signature, algorithm)
				VALUES
				(%s, %s, %s)
				RETURNING key_id, issued, expires;
				""",
				(
					public_key,
					signature,
					self._token_algorithm,
				),
				commit=True,
				fetch_one=True,
			)
			key_id = self._active_private_key['id'] = data[0]
			pk_issued = self._active_private_key['issued'] = data[1].timestamp()
			pk_expires = int(data[2].timestamp())

			# put the new key into the public keyring
			self._public_keyring[(self._token_algorithm, key_id)] = {
				'key': b64encode(public_key).decode(),
				'signature': b64encode(signature).decode(),
				'issued': pk_issued,
				'expires': pk_expires,
			}

		guid: UUID = uuid4()

		load = b'.'.join([
			self._token_algorithm.encode(),
			b64encode(key_id.to_bytes(ceil(key_id.bit_length() / 8), 'big')),
			b64encode(expires.to_bytes(ceil(expires.bit_length() / 8), 'big')),
			b64encode(user_id.to_bytes(ceil(user_id.bit_length() / 8), 'big')),
			b64encode(guid.bytes),
			json.dumps(token_data).encode(),
		])

		token_info: TokenMetadata = TokenMetadata(
			version=self._token_version.encode(),
			state=AuthState.active,
			issued=datetime.fromtimestamp(issued),
			expires=datetime.fromtimestamp(expires),
			key_id=key_id,
			user_id=user_id,
			algorithm=self._token_algorithm,
			fingerprint=token_data.get('fp', '').encode(),
		)
		KVS.put(guid.bytes, token_info, self._token_expires_interval)

		version = self._token_version.encode()
		content = b64encode(version) + b'.' + b64encode(load)
		signature = private_key.sign(content)
		token = content + b'.' + b64encode(signature)

		return {
			'version': self._token_version,
			'algorithm': self._token_algorithm,
			'key_id': key_id,
			'issued': issued,
			'expires': expires,
			'token': token.decode(),
		}


	def fetchPublicKey(self, key_id, algorithm:AuthAlgorithm=None) :
		algorithm = algorithm.name if algorithm else self._token_algorithm.name

		lookup_key = (algorithm, key_id)

		try :

			if lookup_key in self._public_keyring :
				public_key = self._public_keyring[lookup_key]

			else :
				data = self.query("""
					SELECT public_key, signature, issued, expires
					FROM kheina.auth.token_keys
					WHERE algorithm = %s AND key_id = %s;
					""",
					lookup_key,
					fetch_one=True,
				)

				if not data :
					raise NotFound(f'Public key does not exist for algorithm: {algorithm} and key_id: {key_id}.')

				public_key = self._public_keyring[lookup_key] = {
					'key': b64encode(data[0]).decode(),
					'signature': b64encode(data[1]).decode(),
					'issued': data[2].timestamp(),
					'expires': int(data[3].timestamp()),
				}

		except HttpError :
			raise

		except :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			raise InternalServerError('an error occurred while retrieving public key.', logdata={ 'refid': refid })

		return {
			'algorithm': algorithm,
			**public_key,
		}


	def close(self) :
		self._conn.close()
		return self._conn.closed


	def login(self, email: str, password: str, generate_token:bool=False, token_data:Dict[str, Any]={ }) :
		"""
		returns user data on success otherwise raises Unauthorized
		{
			'user_id': int,
			'user': str,
			'name': str,
			'mod': bool,
			'token_data': Optional[dict],
		}
		"""

		if 'scope' in token_data :
			# this is generated here, don't trust incoming data
			del token_data['scope']

		try :
			email_dict: Dict[str, str] = self._validateEmail(email)
			email_hash = self._hash_email(email)
			data = self.query("""
				SELECT
					user_login.user_id,
					user_login.password,
					user_login.secret,
					users.handle,
					users.display_name,
					users.mod
				FROM kheina.auth.user_login
					INNER JOIN kheina.public.users
						ON users.user_id = user_login.user_id
				WHERE email_hash = %s;
				""",
				(email_hash,),
				fetch_one=True,
			)

			if not data :
				raise Unauthorized('login failed.')

			user_id, password_hash, secret, handle, name, mod = data
			password_hash = password_hash.tobytes().decode()

			if not self._argon2.verify(password_hash, password.encode() + self._secrets[secret]) :
				raise Unauthorized('login failed.')

			if self._argon2.check_needs_rehash(password_hash) :
				password_hash = self._argon2.hash(password.encode() + self._secrets[secret]).encode()
				self.query("""
					UPDATE kheina.auth.user_login
					SET password = %s
					WHERE email_hash = %s;
					""",
					(password_hash, email_hash),
					commit=True,
				)

			token = None
			if generate_token :
				if email_dict['domain'] in { 'kheina.com', 'fuzz.ly' } :
					token_data['scope'] = Scope.admin.all_included_scopes()

				elif mod :
					token_data['scope'] = Scope.mod.all_included_scopes()

				self.generate_token(user_id, token_data)

		except HttpError :
			raise

		except :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			raise InternalServerError('an error occurred during verification.', logdata={ 'refid': refid })

		return {
			'user_id': user_id,
			'user': handle,
			'name': name,
			'mod': mod,
			'token_data': token,
		}


	def changePassword(self, email: str, old_password: str, new_password: str) :
		"""
		changes a user's password
		"""
		try :

			email_hash = self._hash_email(email)
			data = self.query("""
				SELECT user_login.user_id, password, secret, handle, display_name
				FROM kheina.auth.user_login
					INNER JOIN kheina.public.users
						ON users.user_id = user_login.user_id
				WHERE email_hash = %s;
				""",
				(email_hash,),
				fetch_one=True,
			)

			if not data :
				raise Unauthorized('password change failed.')

			user_id, password_hash, secret, handle, name = data
			password_hash = password_hash.tobytes()

			if not self._argon2.verify(password_hash.decode(), old_password.encode() + self._secrets[secret]) :
				raise Unauthorized('password change failed.')

			secret = randbelow(len(self._secrets))
			new_password_hash = self._argon2.hash(new_password.encode() + self._secrets[secret]).encode()

		except HttpError :
			raise

		except :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			raise InternalServerError('an error occurred during verification.', logdata={ 'refid': refid })

		self.query("""
			UPDATE kheina.auth.user_login
			SET password = %s,
				secret = %s
			WHERE email_hash = %s;
			""",
			(new_password_hash, secret, email_hash),
			commit=True,
		)


	def create(self, handle: str, name: str, email: str, password: str, token_data:Dict[str, Any]={ }) :
		"""
		returns user data on success otherwise raises Bad Request
		"""
		try :
			email_hash = self._hash_email(email)
			secret = randbelow(len(self._secrets))
			password_hash = self._argon2.hash(password.encode() + self._secrets[secret]).encode()
			data = self.query("""
				WITH new_user AS (
					INSERT INTO kheina.public.users
					(handle, display_name)
					VALUES (%s, %s)
					RETURNING user_id
				)
				INSERT INTO kheina.auth.user_login
				(user_id, email_hash, password, secret)
				SELECT
				new_user.user_id, %s, %s, %s
				FROM new_user
				RETURNING user_id;
				""", (
					handle, name,
					email_hash, password_hash, secret,
				),
				commit=True,
				fetch_one=True,
			)
			return {
				'user_id': data[0],
				'user': handle,
				'name': name,
				'mod': False,
				'token_data': self.generate_token(data[0], token_data),
			}

		except UniqueViolation :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			raise Conflict('a user already exists with that handle or email.', logdata={ 'refid': refid })

		except :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			raise InternalServerError('an error occurred during user creation.', logdata={ 'refid': refid })
