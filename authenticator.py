from argon2 import PasswordHasher as Argon2
from psycopg2 import connect as dbConnect
from base64 import b64encode, b64decode
from secrets import token_bytes
from hashlib import shake_256
from kh_common import logging
import ujson as json


class Authenticator :

	def __init__(self) :
		self._connect()
		self._initArgon2()
		self.logger = logging.getLogger('authenticator')


	def _connect(self) :
		if not self._conn or self._conn.closed :
		with open('credentials/postgres.json') as credentials :
			credentials = json.load(credentials)
			self._conn = dbConnect(dbname='kheina', user=credentials['user'], password=credentials['password'], host=credentials['host'], port='5432')


	def _initArgon2(self) :
		with open('credentials/hashing.json') as credentials :
			credentials = json.load(credentials)
			self._argon2 = Argon2(**credentials['argon2'])
			self._secrets = credentials['salts']


	def _query(sql, params=(), maxretry=2) :
		try :
			cur = conn.cursor()
			cur.execute(sql, params)
			return cur.fetchall()

		except psycopg2.DataError :
			e, exc_tb = sys.exc_info()[1:]
			self.logger.warning({ 'message': f'{getFullyQualifiedClassName(e)}: {e}', 'stacktrace': format_tb(exc_tb) })
			# now attempt to recover by rolling back
			conn.rollback()

		except (psycopg2.IntegrityError, psycopg2.errors.InFailedSqlTransaction) :
			self._connect()
			if maxattempts > 1 :
				e, exc_tb = sys.exc_info()[1:]
				self.logger.warning({ 'message': f'{getFullyQualifiedClassName(e)}: {e}', 'stacktrace': format_tb(exc_tb) })
				return query(data, maxattempts=maxattempts-1)
			else :
				self.logger.exception({ })
				raise

		finally :
			# don't commit to avoid modifying or corrupting the database
			cur.close()


	def verify(self, cookie) :
		pass


	def verify(self, email, password) :
		# always use the first secret since we can't retrieve the record without hashing it
		email_hash = shake_256(email + self._secrets[0]).digest(256)



	def create(self, email, password) :
		pass
