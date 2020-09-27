from models import ChangePasswordRequest, CreateUserRequest, LoginRequest, PublicKeyRequest
from kh_common.exceptions import jsonErrorHandler
from kh_common.validation import validatedJson
from starlette.responses import UJSONResponse
from authenticator import Authenticator


authServer = Authenticator()


@jsonErrorHandler
@validatedJson
async def v1PublicKey(req: PublicKeyRequest) :
	return UJSONResponse(
		authServer.fetchPublicKey(req.key_id, req.algorithm)
	)


@jsonErrorHandler
@validatedJson
async def v1Login(req: LoginRequest) :
	return UJSONResponse(
		authServer.login(
			req.email,
			req.password,
			req.generate_token or bool(req.token_data),
			req.token_data,
		)
	)


@jsonErrorHandler
@validatedJson
async def v1CreateUser(req: CreateUserRequest) :
	return UJSONResponse(
		authServer.create(req.handle, req.name, req.email, req.password)
	)


@jsonErrorHandler
@validatedJson
async def v1ChangePassword(req: ChangePasswordRequest) :
	return UJSONResponse(
		authServer.changePassword(req.email, req.old_password, req.new_password)
	)


async def v1Help(req) :
	return UJSONResponse({
		'/v1/key': {
			'version': 'Optional[str]',
			'algorithm': 'Optional[str]',
			'key_id': 'int',
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
		'/v1/change_password': {
			'email': 'str',
			'old_password': 'str',
			'new_password': 'str',
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
	Middleware(TrustedHostMiddleware, allowed_hosts={ 'localhost', '127.0.0.1', 'auth.kheina.com', 'auth-dev.kheina.com' }),
]

routes = [
	Route('/v1/key', endpoint=v1PublicKey, methods=('POST',)),
	Route('/v1/login', endpoint=v1Login, methods=('POST',)),
	Route('/v1/create', endpoint=v1CreateUser, methods=('POST',)),
	Route('/v1/change_password', endpoint=v1ChangePassword, methods=('POST',)),
	Route('/v1/help', endpoint=v1Help, methods=('GET',)),
]

app = Starlette(
	routes=routes,
	middleware=middleware,
	on_shutdown=[shutdown],
)

if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='127.0.0.1', port=5000)
