from psycopg2 import connect as dbConnect, Binary, IntegrityError, DataError, errors
from secrets import token_bytes, randbelow, compare_digest
from kh_common import getFullyQualifiedClassName, logging
from argon2 import PasswordHasher as Argon2
from base64 import b64encode, b64decode
from traceback import format_tb
from hashlib import sha3_512
from uuid import uuid4
import ujson as json
import sys


class Authenticator :

	def __init__(self) :
		self._connect()
		self._initArgon2()
		self.logger = logging.getLogger('auth')


	def _connect(self) :
		with open('credentials/postgres.json') as credentials :
			credentials = json.load(credentials)
			self._conn = dbConnect(dbname='kheina', user=credentials['user'], password=credentials['password'], host=credentials['host'], port='5432')


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
			return cur.fetchall() if fetch else None
		except DataError :
			e, exc_tb = sys.exc_info()[1:]
			self.logger.warning({ 'message': f'{getFullyQualifiedClassName(e)}: {e}', 'stacktrace': format_tb(exc_tb) })
			# now attempt to recover by rolling back
			self._conn.rollback()
		except (IntegrityError, errors.InFailedSqlTransaction) :
			self._connect()
			if maxretry > 1 :
				e, exc_tb = sys.exc_info()[1:]
				self.logger.warning({ 'message': f'{getFullyQualifiedClassName(e)}: {e}', 'stacktrace': format_tb(exc_tb) })
				return self._query(sql, params, commit, fetch, maxretry - 1)
			else :
				self.logger.exception({ })
				raise
		finally :
			cur.close()


	def _hash_email(self, email) :
		# always use the first secret since we can't retrieve the record without hashing it
		return sha3_512(email.encode() + self._secrets[0]).digest()


	def _hash_key(self, key, salt, secret) :
		return sha3_512(key + salt + self._secrets[secret]).digest()


	def _generate_key(self) :
		# 44 for a round base64 character when paired with uuid
		key = token_bytes(44)
		salt = token_bytes(44)
		secret = randbelow(len(self._secrets))
		return key, salt, secret, self._hash_key(key, salt, secret)


	def close(self) :
		self._conn.close()
		return self._conn.closed


	def verifyKey(self, key) :
		"""
		key = b64encode(ref_id + key_hash)
		returns user data on success otherwise None
		{
			"user_id": int,
			"user": str,
			"name": str,
			"icon": str,
			"key": str,
		}
		"""
		try :
			key_load = b64decode(key)
			ref_id = key_load[:16].hex()
			key_load = key_load[16:]
			data = self._query("""
				SELECT user_auth.user_id, key, salt, secret, handle, display_name, post_id
				FROM user_auth
					INNER JOIN users
						ON users.user_id = user_auth.user_id
					LEFT JOIN user_icon
						ON user_auth.user_id = user_icon.user_id
				WHERE ref_id = %s;
				""",
				(ref_id,),
				fetch=True,
			)
			if not data :
				return {
					'error': 'verification failed.',
				}

			user_id, key_hash, salt, secret, handle, display_name, post_id = data[0]

			if compare_digest(key_hash, self._hash_key(key_load, salt, secret)) :
				return {
					'user_id': user_id,
					'user': handle,
					'name': display_name,
					'icon': post_id,
					'key': key,
				}
			else :
				return {
					'error': 'verification failed.',
				}
		except :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			return {
				'error': 'verification failed.',
				'refid': refid,
			}


	def verifyLogin(self, email, password, generateKey=False) :
		"""
		returns user data on success otherwise error dict
		{
			"user_id": int,
			"user": str,
			"name": str,
			"icon": str,
			"key": str,
		}
		"""
		try :
			email_hash = self._hash_email(email)
			data = self._query("""
				SELECT user_login.user_id, password, secret, handle, display_name, post_id
				FROM user_login
					INNER JOIN users
						ON users.user_id = user_login.user_id
					LEFT JOIN user_icon
						ON user_login.user_id = user_icon.user_id
				WHERE email_hash = %s;
				""",
				(Binary(email_hash),),
				fetch=True,
			)
			if not data :
				return {
					'error': 'verification failed.',
				}
			user_id, password_hash, secret, handle, name, post_icon = data[0]

			password_hash = password_hash.tobytes().decode()

			if not self._argon2.verify(password_hash, password.encode() + self._secrets[secret]) :
				return None

			if self._argon2.check_needs_rehash(password_hash) :
				password_hash = self._argon2.hash(password.encode() + self._secrets[secret]).encode()
				self._query("""
					UPDATE user_login
					SET password = %s
					WHERE email_hash = %s;
					""",
					(Binary(password_hash), Binary(email_hash)),
					commit=True,
				)

			key = None
			if generateKey :
				key, key_salt, key_secret, key_hash = self._generate_key()
				data = self._query("""
					INSERT INTO user_auth
					(user_id, key, salt, secret)
					VALUES
					(%s, %s, %s, %s)
					RETURNING
					ref_id;
					""",
					(user_id, Binary(key_hash), Binary(key_salt), key_secret),
					commit=True,
					fetch=True,
				)
				key = bytes.fromhex(data[0][0].replace('-', '')) + key

			return {
				'user_id': user_id,
				'user': handle,
				'name': name,
				'icon': post_icon,
				'key': b64encode(key).decode() if key else None,
			}
		except:
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			return {
				'error': 'verification failed.',
				'refid': refid,
			}


	def create(self, handle, name, email, password) :
		"""
		returns: None on success, otherwise error dict
		"""
		try :
			email_hash = self._hash_email(email)
			secret = randbelow(len(self._secrets))
			password_hash = self._argon2.hash(password.encode() + self._secrets[secret]).encode()
			data = self._query("""
				INSERT INTO users
				(handle, display_name)
				VALUES
				(%s, %s);

				INSERT INTO user_login
				(user_id, email_hash, password, secret)
				SELECT
				user_id, %s, %s, %s
				FROM users
				WHERE handle = %s
				RETURNING user_id;
				""", (
					handle, name,
					Binary(email_hash), Binary(password_hash), secret,
					handle,
				),
				commit=True,
				fetch=True,
			)
			return {
				'user_id': data[0][0],
				'user': handle,
				'name': name,
			}
		except :
			refid = uuid4().hex
			self.logger.exception({ 'refid': refid })
			return {
				'error': 'creation failed.',
				'refid': refid,
			}
