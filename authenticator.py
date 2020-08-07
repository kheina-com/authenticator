from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from kh_common.http_error import Unauthorized, BadRequest, InternalServerError, NotFound
from cryptography.hazmat.backends import default_backend as crypto_backend
from psycopg2.errors import UniqueViolation, ConnectionException
from secrets import token_bytes, randbelow, compare_digest
from kh_common import getFullyQualifiedClassName, logging
from cryptography.hazmat.primitives import serialization
from kh_common.base64 import b64encode, b64decode
from psycopg2 import Binary, connect as dbConnect
from argon2 import PasswordHasher as Argon2
from traceback import format_tb
from hashlib import sha3_512
from math import floor, ceil
from uuid import uuid4
from time import time
import ujson as json
import sys


"""
table definition:
CREATE TABLE kheina.auth.token_keys (
	key_id INT UNIQUE GENERATED ALWAYS AS IDENTITY,
	algorithm TEXT NOT NULL,
	public_key BYTEA NOT NULL,
	private_key BYTEA NOT NULL,
	secret SMALLINT NOT NULL,
	issued TIMESTAMPTZ NOT NULL DEFAULT now(),
	expires TIMESTAMPTZ NOT NULL DEFAULT current_date + interval '30 days',
	PRIMARY KEY (algorithm, key_id)
);
CREATE INDEX token_keys_algorithm_issued_expires_joint_index ON kheina.auth.token_keys (algorithm, issued, expires);
"""


def verifyToken(token) :
	load, signature = tuple(map(b64decode, token.split('.')))
	version, algorithm, key_id, expires, guid, data = load.split(b'.', 5)
	version = version.decode()
	algorithm = algorithm.decode()
	key_id = int.from_bytes(b64decode(key_id), 'big')
	expires = int.from_bytes(b64decode(expires), 'big')
	guid = b64decode(guid).hex()

	# fetchPublicKey = lambda expires : a.fetchPublicKey(key_id, algorithm).get('key')
	public_key = Ed25519PublicKey.from_public_bytes(
		b64decode(fetchPublicKey(key_id, algorithm))
	)
	public_key.verify(signature, load)

	return json.loads(data)


class Authenticator :

	def __init__(self) :
		self.logger = logging.getLogger('auth')
		self._connect()
		self._initArgon2()
		self._key_refresh_interval = 60 * 60 * 24  # 24 hours
		self._token_expires_interval = 60 * 60 * 24 * 30  # 30 days
		self._token_version = '1'
		self._token_algorithm = 'ed25519'
		self._public_keyring = { }
		self._active_private_key = {
			'key': None,
			'algorithm': None,
			'issued': 0,
			'start': 0,
			'end': 0,
			'id': 0,
		}


	def _connect(self) :
		with open('credentials/postgres.json') as credentials :
			credentials = json.load(credentials)
			try :
				self._conn = dbConnect(dbname='kheina', user=credentials['user'], password=credentials['password'], host=credentials['host'], port='5432')

			except Exception as e :
				self.logger.critical({ 'message': f'failed to connect to database!', 'error': f'{getFullyQualifiedClassName(e)}: {e}' })

			else :
				self.logger.info(f'connected to database.')


	def _initArgon2(self) :
		with open('credentials/hashing.json') as credentials :
			credentials = json.load(credentials)
			self._argon2 = Argon2(**credentials['argon2'])
			self._secrets = [bytes.fromhex(salt) for salt in credentials['salts']]


	def _query(self, sql, params=(), commit=False, fetch_one=False, fetch_all=False, maxretry=2) :
		try :
			cur = self._conn.cursor()
			cur.execute(sql, params)

			if commit :
				self._conn.commit()
			else :
				self._conn.rollback()

			if fetch_one :
				return cur.fetchone()
			elif fetch_all :
				return cur.fetchall()

		except ConnectionException :
			self._connect()
			if maxretry > 1 :
				e, exc_tb = sys.exc_info()[1:]
				self.logger.warning({ 'message': f'{getFullyQualifiedClassName(e)}: {e}', 'stacktrace': format_tb(exc_tb) })
				return self._query(sql, params, commit, fetch_one, fetch_all, maxretry - 1)
			else :
				self.logger.exception({ })
				raise

		except :
			e, exc_tb = sys.exc_info()[1:]
			self.logger.warning({ 'message': f'{getFullyQualifiedClassName(e)}: {e}', 'stacktrace': format_tb(exc_tb) })
			# now attempt to recover by rolling back
			self._conn.rollback()
			raise

		finally :
			cur.close()


	def _hash_email(self, email) :
		# always use the first secret since we can't retrieve the record without hashing it
		return sha3_512(email.encode() + self._secrets[0]).digest()


	def _calc_timestamp(self, timestamp) :
		return int(self._key_refresh_interval * floor(timestamp / self._key_refresh_interval))


	def _generate_token(self, token_data: dict) :
		issued = time()
		expires = self._calc_timestamp(issued) + self._token_expires_interval

		if self._active_private_key['start'] <= issued < self._active_private_key['end'] :
			private_key = self._active_private_key['key']
			issued = self._active_private_key['issued']
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

			# look for an existing private key in the db
			data = self._query("""
				SELECT private_key, secret, key_id, issued, expires
				FROM kheina.auth.token_keys
				WHERE
					algorithm = %s
					AND issued BETWEEN to_timestamp(%s)
						AND to_timestamp(%s);
				""",
				(self._token_algorithm, start, end),
				fetch_one=True,
			)

			if data :
				pk_load = data[0]
				secret = data[1]
				key_id = self._active_private_key['id'] = data[2]
				issued = self._active_private_key['issued'] = data[3].timestamp()
				expires = int(data[4].timestamp())

				private_key = self._active_private_key['key'] = serialization.load_der_private_key(pk_load, self._secrets[secret], crypto_backend())
				public_key = private_key.public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				)
				del data, pk_load, secret

			else :
				secret = randbelow(len(self._secrets))
				private_key = self._active_private_key['key'] = Ed25519PrivateKey.generate()
				public_key = private_key.public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				)

				# insert the new key into db
				data = self._query("""
					INSERT INTO kheina.auth.token_keys
					(public_key, private_key, secret, algorithm)
					VALUES
					(%s, %s, %s, %s)
					RETURNING key_id, issued, expires;
					""",
					(
						public_key,
						private_key.private_bytes(
							encoding=serialization.Encoding.DER,
							format=serialization.PrivateFormat.PKCS8,
							encryption_algorithm=serialization.BestAvailableEncryption(self._secrets[secret]),
						),
						secret,
						self._token_algorithm,
					),
					commit=True,
					fetch_one=True,
				)
				key_id = self._active_private_key['id'] = data[0]
				issued = self._active_private_key['issued'] = data[1].timestamp()
				expires = int(data[2].timestamp())

			# put the new key into the public keyring
			self._public_keyring[(self._token_algorithm, key_id)] = {
				'key': b64encode(public_key).decode(),
				'issued': issued,
				'expires': expires,
			}

		load = b'.'.join([
			self._token_version.encode(),
			self._token_algorithm.encode(),
			b64encode(key_id.to_bytes(ceil(key_id.bit_length() / 8), 'big')),
			b64encode(expires.to_bytes(ceil(expires.bit_length() / 8), 'big')),
			b64encode(uuid4().bytes),
			json.dumps(token_data).encode(),
		])
		token = b64encode(load) + b'.' + b64encode(private_key.sign(load))

		return {
			'version': self._token_version,
			'algorithm': self._token_algorithm,
			'issued': time(),  # token issued is always current time
			'expires': expires,
			'token': token.decode(),
		}

	
	def fetchPublicKey(self, key_id, algorithm=None) :
		if not algorithm :
			algorithm = self._token_algorithm

		lookup_key = (algorithm, key_id)

		if lookup_key in self._public_keyring :
			public_key = self._public_keyring[lookup_key]

		else :
			data = self._query("""
				SELECT public_key, issued, expires
				FROM kheina.auth.token_keys
				WHERE algorithm = %s AND key_id = %s;
				""",
				lookup_key,
				fetch_one=True,
			)

			if not data :
				raise NotFound('Public key does not exist for given algorithm and key_id.')

			public_key = self._public_keyring[lookup_key] = {
				'key': b64encode(data[0]).decode(),
				'issued': data[1].timestamp(),
				'expires': int(data[2].timestamp()),
			}

		return {
			'algorithm': algorithm,
			**public_key,
		}


	def close(self) :
		self._conn.close()
		return self._conn.closed


	def login(self, email, password, generate_token=False, token_data=None) :
		"""
		returns user data on success otherwise raises Unauthorized
		{
			"user_id": int,
			"user": str,
			"name": str,
			"token": str,
		}
		"""
		try :
			email_hash = self._hash_email(email)
			data = self._query("""
				SELECT user_login.user_id, password, secret, handle, display_name
				FROM kheina.auth.user_login
					INNER JOIN users
						ON users.user_id = user_login.user_id
				WHERE email_hash = %s;
				""",
				(Binary(email_hash),),
				fetch_one=True,
			)
			if not data :
				raise Unauthorized('verification failed.')

			user_id, password_hash, secret, handle, name = data
			password_hash = password_hash.tobytes().decode()

			if not self._argon2.verify(password_hash, password.encode() + self._secrets[secret]) :
				raise Unauthorized('verification failed.')

			if self._argon2.check_needs_rehash(password_hash) :
				password_hash = self._argon2.hash(password.encode() + self._secrets[secret]).encode()
				self._query("""
					UPDATE kheina.auth.user_login
					SET password = %s
					WHERE email_hash = %s;
					""",
					(Binary(password_hash), Binary(email_hash)),
					commit=True,
				)

			if generate_token :
				if token_data :
					load = { **token_data, 'user_id': user_id }
				else :
					load = { 'user_id': user_id }

				token = self._generate_token(load) if generate_token else None

			return {
				'user_id': user_id,
				'user': handle,
				'name': name,
				'token': token if generate_token else None,
			}

		except:
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			raise InternalServerError('verification failed.', logdata={ 'refid': refid })


	def create(self, handle, name, email, password) :
		"""
		returns user data on success otherwise raises Bad Request
		"""
		try :
			email_hash = self._hash_email(email)
			secret = randbelow(len(self._secrets))
			password_hash = self._argon2.hash(password.encode() + self._secrets[secret]).encode()
			data = self._query("""
					WITH new_user AS (
						INSERT INTO users
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
					Binary(email_hash), Binary(password_hash), secret,
				),
				commit=True,
				fetch_one=True,
			)
			return {
				'user_id': data[0],
				'user': handle,
				'name': name,
				'token': None,
			}

		except UniqueViolation :
			raise BadRequest('a user already exists with that handle or email.')

		except :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			raise InternalServerError('user creation failed.', logdata={ 'refid': refid })
