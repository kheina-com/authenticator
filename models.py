from datetime import datetime
from enum import Enum, unique
from typing import Any, Dict, Optional

from avrofastapi.schema import AvroInt
from pydantic import BaseModel


@unique
class AuthAlgorithm(Enum) :
	ed25519: str = 'ed25519'


class TokenRequest(BaseModel) :
	user_id: int = 0
	token_data: Dict[str, Any]


class PublicKeyRequest(BaseModel) :
	key_id: int
	algorithm: AuthAlgorithm
	version: Optional[str]


class LoginRequest(BaseModel) :
	email: str
	password: str
	token_data: Optional[Dict[str, Any]] = { }


class TokenResponse(BaseModel) :
	version: str
	algorithm: AuthAlgorithm
	key_id: int
	issued: int
	expires: int
	token: str


class LoginResponse(BaseModel) :
	user_id: int
	handle: str
	name: Optional[str]
	mod: bool
	token: TokenResponse


class CreateUserRequest(BaseModel) :
	name: str
	handle: str
	email: str
	password: str
	token_data: Optional[Dict[str, Any]] = { }


class ChangePasswordRequest(BaseModel) :
	email: str
	old_password: str
	new_password: str


class BotLogin(BaseModel) :
	bot_id: int
	user_id: Optional[int]
	password: bytes
	secret: AvroInt


class BotType(Enum) :
	"""
	this enum maps to a db type.
	"""
	internal: int = 1
	bot: int = 2


class BotCreateResponse(BaseModel) :
	token: str


class BotLoginRequest(BaseModel) :
	token: str


class PublicKeyResponse(BaseModel) :
	algorithm: AuthAlgorithm
	key: str
	signature: str
	issued: datetime
	expires: datetime
