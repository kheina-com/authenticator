from kh_common import logging, getFullyQualifiedClassName
from starlette.responses import UJSONResponse
from authenticator import Authenticator
from traceback import format_tb
import ujson as json
import time
import sys


logger = logging.getLogger('auth')
authServer = Authenticator()


async def JSONErrorHandler(req) :
	exc_type, e, exc_tb = sys.exc_info()
	status = getattr(e, 'status', 500)

	error = {
		'error': f'{status} {getFullyQualifiedClassName(e)}: {e}',
		'status': status,
		'method': req.method,
		'url': str(req.url),
		**getattr(e, 'logdata', { }),
	}
	return UJSONResponse(
		error,
		status_code=status,
	)


async def v1publicKey(req) :
	"""
	{
		"version": Optional[str],
		"algorithm": Optional[str],
		"expires": float
	}
	"""
	try :
		requestJson = await req.json()

		expires = requestJson.get('expires')
		algorithm = requestJson.get('algorithm')
		version = requestJson.get('version')
		if expires :
			return UJSONResponse(authServer.fetchPublicKey(expires, algorithm))

		else :
			return UJSONResponse({
				'error': 'no expires provided.',
			})

	except :
		return await JSONErrorHandler(req)


async def v1authorizeLogin(req) :
	"""
	{
		"email": str,
		"password": str,
		"generate_token": Optional[bool],
		"token_data": Optional[dict]
	}
	"""
	try :
		requestJson = await req.json()

		email = requestJson.get('email')
		password = requestJson.get('password')
		new_token = requestJson.get('generate_token')
		token_data = requestJson.get('generate_token')

		if email and password :
			return UJSONResponse(
				authServer.login(
					email,
					password,
					generate_token=True if new_token or token_data else None,
					token_data=token_data
				)
			)
		
		else :
			return UJSONResponse({
				'error': 'email or password missing.',
			})

	except :
		return await JSONErrorHandler(req)


async def v1createUser(req) :
	"""
	{
		"name": str,
		"handle": str,
		"email": str,
		"password": str
	}
	"""
	try :
		requestJson = await req.json()

		name = requestJson.get('name')
		handle = requestJson.get('handle')
		email = requestJson.get('email')
		password = requestJson.get('password')

		if name and handle and email and password :
			return UJSONResponse(authServer.create(handle, name, email, password))

		else :
			return UJSONResponse({
				'error': 'parameter missing.',
			})

	except :
		return await JSONErrorHandler(req)


async def v1help(req) :
	return UJSONResponse({
		'/v1/key': {
			'version': 'Optional[str]',
			'algorithm': 'Optional[str]',
			'expires': 'float',
		},
		'/v1/login': {
			'email': 'str',
			'password': 'str',
			'generate_token': 'Optional[bool]',
			'token_data': 'Optional[dict]',
		},
		'/v1/create': {
			'name': 'str',
			'handle': 'str',
			'email': 'str',
			'password': 'str',
		},
	})


async def shutdown() :
	authServer.close()


from starlette.applications import Starlette
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Route, Mount

middleware = [
	# Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts),
]

routes = [
	Route('/v1/key', endpoint=v1authorizeKey, methods=('POST',)),
	Route('/v1/login', endpoint=v1authorizeLogin, methods=('POST',)),
	Route('/v1/create', endpoint=v1createUser, methods=('POST',)),
	Route('/v1/help', endpoint=v1help, methods=('GET',)),
]

app = Starlette(
	routes=routes,
	middleware=middleware,
	on_shutdown=[shutdown],
)

if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='127.0.0.1', port=80)
