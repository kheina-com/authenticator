from models import ChangePasswordRequest, CreateUserRequest, LoginRequest, PublicKeyRequest
from starlette.middleware.trustedhost import TrustedHostMiddleware
from kh_common.exceptions import jsonErrorHandler
from starlette.responses import UJSONResponse
from authenticator import Authenticator
from fastapi import FastAPI


app = FastAPI()
app.add_exception_handler(Exception, jsonErrorHandler)
app.add_middleware(TrustedHostMiddleware, allowed_hosts={ 'localhost', '127.0.0.1', 'auth.kheina.com', 'auth-dev.kheina.com' })

authServer = Authenticator()


@app.on_event('shutdown')
async def shutdown() :
	authServer.close()


@app.post('/v1/key')
async def v1PublicKey(req: PublicKeyRequest) :
	return UJSONResponse(
		authServer.fetchPublicKey(req.key_id, req.algorithm)
	)


@app.post('/v1/login')
async def v1Login(req: LoginRequest) :
	return UJSONResponse(
		authServer.login(
			req.email,
			req.password,
			req.generate_token,
			req.token_data,
		)
	)


@app.post('/v1/create')
async def v1CreateUser(req: CreateUserRequest) :
	return UJSONResponse(
		authServer.create(req.handle, req.name, req.email, req.password)
	)


@app.post('/v1/change_password')
async def v1ChangePassword(req: ChangePasswordRequest) :
	return UJSONResponse(
		authServer.changePassword(req.email, req.old_password, req.new_password)
	)


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='127.0.0.1', port=5000)
