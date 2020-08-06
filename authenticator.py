from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from kh_common.http_error import Unauthorized, BadRequest, InternalServerError
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
from uuid import uuid4
from math import floor
from time import time
import ujson as json
import sys


def verifyToken(token) :
	load, signature = tuple(map(b64decode, token.split('.')))
	version, algorithm, expires, guid, data = b64decode(load).split(b'.', 4)

	# fetchPublicKey = lambda expires : a.fetchPublicKey(expires).get('public_key')
	public_key = Ed25519PublicKey.from_public_bytes(
		b64decode(fetchPublicKey(version, algorithm, expires))
	)
	public_key.verify(b64decode(signature), load)

	return {
		'user_id': int(user_id),
	}


class Authenticator :

	def __init__(self) :
		self.logger = logging.getLogger('auth')
		self._connect()
		self._initArgon2()
		self._key_refresh_interval = 60 * 60 * 24  # 24 hours
		self._token_expires_interval = 60 * 60 * 24 * 30  # 30 days
		self._private_keys = { }
		self._token_version = '1'
		self._token_algorithm = 'ed25519'


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


	def _query(self, sql, params=(), commit=False, fetch=False, maxretry=2) :
		try :
			cur = self._conn.cursor()
			cur.execute(sql, params)
			if commit :
				self._conn.commit()
			else :
				self._conn.rollback()
			return cur.fetchall() if fetch else None

		except ConnectionException :
			self._connect()
			if maxretry > 1 :
				e, exc_tb = sys.exc_info()[1:]
				self.logger.warning({ 'message': f'{getFullyQualifiedClassName(e)}: {e}', 'stacktrace': format_tb(exc_tb) })
				return self._query(sql, params, commit, fetch, maxretry - 1)
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


	def _calc_expires(self, timestamp) :
		return self._key_refresh_interval * round(timestamp / self._key_refresh_interval)


	def _generate_token(self, token_data) :
		expires = self._calc_expires(time()) + self._token_expires_interval

		if expires in self._private_keys :
			private_key = self._private_keys[expires]

		else :
			# look for an existing public/private key in the db
			data = self._query("""
				SELECT private_key, secret
				FROM kheina.auth.token_key
				WHERE algorithm = %s AND expires = to_timestamp(%s);
				""",
				(self._token_algorithm, expires),
				fetch=True,
			)

			if data :
				pk_load = data[0][0]
				secret = data[0][1]
				private_key = self._private_keys[expires] = serialization.load_der_private_key(pk_load, self._secrets[secret], crypto_backend())
				del data, pk_load, secret

			else :
				secret = randbelow(len(self._secrets))
				private_key = self._private_keys[expires] = Ed25519PrivateKey.generate()

				# insert the new key into db
				self._query("""
					INSERT INTO kheina.auth.token_key
					(algorithm, public_key, private_key, secret, expires)
					VALUES
					(%s, %s, %s, %s, to_timestamp(%s));
					""",
					(
						self._token_algorithm,
						private_key.public_key().public_bytes(
							encoding=serialization.Encoding.Raw,
							format=serialization.PublicFormat.Raw
						),
						private_key.private_bytes(
							encoding=serialization.Encoding.DER,
							format=serialization.PrivateFormat.PKCS8,
							encryption_algorithm=serialization.BestAvailableEncryption(self._secrets[secret])
						),
						secret,
						expires,
					),
					commit=True,
				)

		load = f'{self._token_version}.{self._token_algorithm}.{expires}.{uuid4().hex}.{json.dumps(token_data)}'.encode()
		token = b64encode(load) + b'.' + b64encode(private_key.sign(load))

		return {
			'version': self._token_version,
			'algorithm': self._token_algorithm,
			'expires': expires,
			'token': token.decode(),
		}

	
	def fetchPublicKey(self, expires, algorithm=None) :
		if expires < time() :
			raise Unauthorized('Token has expired.')

		if not algorithm :
			algorithm = self._token_algorithm

		expires = self._calc_expires(expires)
		public_key = None

		if expires in self._private_keys :
			public_key = self._private_keys[expires].public_key().public_bytes(
				encoding=serialization.Encoding.Raw,
				format=serialization.PublicFormat.Raw,
			)

		else :
			data = self._query("""
				SELECT public_key
				FROM kheina.auth.token_key
				WHERE algorithm = %s AND expires = to_timestamp(%s);
				""",
				(algorithm, expires),
				fetch=True,
			)
			if data :
				public_key = data[0][0]

		if public_key :
			return {
				'algorithm': algorithm,
				'expires': expires,
				'public_key': bytes.decode(b64encode(public_key)),
			}

		raise InternalServerError('Public key does not exist for given expire and algorithm.')


	def close(self) :
		self._conn.close()
		return self._conn.closed


	def login(self, email, password, generateToken=False) :
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
				fetch=True,
			)
			if not data :
				raise Unauthorized('verification failed.')

			user_id, password_hash, secret, handle, name = data[0]
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

			token = self._generate_token({ 'user_id': user_id }) if generateToken else None

			return {
				'user_id': user_id,
				'user': handle,
				'name': name,
				'token': token,
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
				fetch=True,
			)
			return {
				'user_id': data[0][0],
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
