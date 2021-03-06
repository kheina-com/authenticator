from models import ChangePasswordRequest, CreateUserRequest, LoginRequest, PublicKeyRequest, TokenRequest
from kh_common.server import ServerApp, UJSONResponse
from authenticator import Authenticator


app = ServerApp(auth=False, cors=False)
authServer = Authenticator()


@app.on_event('shutdown')
async def shutdown() :
	authServer.close()


@app.post('/v1/key')
async def v1PublicKey(req: PublicKeyRequest) :
	return UJSONResponse(
		authServer.fetchPublicKey(req.key_id, req.algorithm)
	)


@app.post('/v1/sign_data')
async def v1SignData(req: TokenRequest) :
	return UJSONResponse(
		authServer.generate_token(req.user_id, req.token_data)
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
		authServer.create(req.handle, req.name, req.email, req.password, req.token_data)
	)


@app.post('/v1/change_password')
async def v1ChangePassword(req: ChangePasswordRequest) :
	return UJSONResponse(
		authServer.changePassword(req.email, req.old_password, req.new_password)
	)


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='127.0.0.1', port=5000)
