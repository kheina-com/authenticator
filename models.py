from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel
from enum import Enum, unique


@unique
class AuthAlgorithm(Enum) :
	ed25519: str = 'ed25519'


class PublicKeyRequest(BaseModel) :
	key_id: int
	algorithm: AuthAlgorithm
	version: Optional[str]


class LoginRequest(BaseModel) :
	email: str
	password: str
	new_token: Optional[bool] = True
	token_data: Optional[Dict[str, Any]] = { }


class CreateUserRequest(BaseModel) :
	name: str
	handle: str
	email: str
	password: str


class ChangePasswordRequest(BaseModel) :
	email: str
	old_password: str
	new_password: str
