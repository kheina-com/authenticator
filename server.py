from kh_common import logging, getFullyQualifiedClassName
from starlette.responses import UJSONResponse
from authenticator import Authenticator
from traceback import format_tb
from uuid import uuid4
import ujson as json
import time


logger = logging.getLogger('auth')
authServer = Authenticator()


async def JSONErrorHandler(req) :
	exc_type, e, exc_tb = sys.exc_info()
	status = getattr(e, 'status', 500)

	error = {
		'error': f'{status} {getFullyQualifiedClassName(e)}: {e}',
		'status': status,
		'stacktrace': format_tb(exc_tb),
		'method': req.method,
		'url': str(req.url),
		'refid': uuid4().hex,
		**getattr(e, 'logdata', { }),
	}
	logger.error(error)
	return UJSONResponse(
		error,
		status_code=status,
		# headers={ },
	)


async def v1authorizeKey(req) :
	"""
	{ "key": str }
	"""
	try :
		requestJson = await req.json()

		key = requestJson.get('key')
		if key :
			return UJSONResponse(authServer.verifyKey(key))
		
		else :
			return UJSONResponse({
				'error': 'no key provided.',
			})

	except :
		return await JSONErrorHandler(req)


async def v1authorizeLogin(req) :
	"""
	{
		"email": str,
		"password": str,
		"generate_key": bool
	}
	"""
	try :
		requestJson = await req.json()

		email = requestJson.get('email')
		password = requestJson.get('password')
		newKey = requestJson.get('generate_key')

		if email and password :
			return UJSONResponse(authServer.verifyLogin(email, password, generateKey=newKey))
		
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
]

app = Starlette(
	routes=routes,
	middleware=middleware,
	on_shutdown=[shutdown],
)

if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='127.0.0.1', port=80)
