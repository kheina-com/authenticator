from fastapi.responses import UJSONResponse
from kh_common.auth import Scope
from kh_common.server import Request, ServerApp

from authenticator import Authenticator
from models import BotLoginRequest, ChangePasswordRequest, CreateUserRequest, LoginRequest, LoginResponse, PublicKeyRequest, PublicKeyResponse, TokenRequest, TokenResponse


app = ServerApp(auth_required=False, cors=False)
authServer = Authenticator()


@app.on_event('shutdown')
async def shutdown() :
	authServer.close()


@app.post('/v1/key', response_model=PublicKeyResponse)
def v1PublicKey(body: PublicKeyRequest) :
	return authServer.fetchPublicKey(body.key_id, body.algorithm)


@app.post('/v1/sign_data', response_model=TokenResponse)
async def v1SignData(req: Request, body: TokenRequest) :
	await req.user.verify_scope(Scope.internal)
	# we would like to be able to sign arbitrary data, but that opens up a world of spoofing issues, so we're restricting to only user 0 for now
	return authServer.generate_token(0, body.token_data)


@app.post('/v1/login', response_model=LoginResponse)
async def v1Login(req: Request, body: LoginRequest) :
	await req.user.verify_scope(Scope.internal)
	return authServer.login(
		body.email,
		body.password,
		body.token_data,
	)


@app.post('/v1/create', response_model=LoginResponse)
async def v1CreateUser(req: Request, body: CreateUserRequest) -> LoginResponse :
	await req.user.verify_scope(Scope.internal)
	return authServer.create(body.handle, body.name, body.email, body.password, body.token_data)


@app.post('/v1/change_password', status_code=204)
async def v1ChangePassword(req: Request, body: ChangePasswordRequest) :
	await req.user.verify_scope(Scope.internal)
	return authServer.changePassword(body.email, body.old_password, body.new_password)


@app.post('/v1/bot_login', response_model=LoginResponse)
async def v1ChangePassword(req: Request, body: BotLoginRequest) :
	await req.user.verify_scope(Scope.internal)
	return authServer.botLogin(body.token)


if __name__ == '__main__' :
	from uvicorn.main import run
	run(app, host='127.0.0.1', port=5000)
