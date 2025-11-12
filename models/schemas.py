from pydantic import BaseModel
from typing import Optional

class CipherRequest(BaseModel):
    text: str
    shift: int


class PolyRequest(BaseModel):
    text: str
    key: str


class PlayFairRequest(BaseModel):
    text: str
    key: str



class DESRequest(BaseModel):
    text: str
    key: str

class AESRequest(BaseModel):
    text:str
    encrypted_blocks: list

class RC4Request(BaseModel):
    key:str
    text:str

class RSARequest(BaseModel):
    key:tuple
    text:str

class HashRequest(BaseModel):
    text: str
    hash: Optional[str] ="md5"
    algo: Optional[str] ="sha256"
    

class RSAVerifyRequest(BaseModel):
    key:tuple
    text:str
    sign:Optional[str]=''

class ECDSARequest(BaseModel):
    key:Optional[tuple] = None
    private: Optional[int] = 0
    text:str
    sign:Optional[tuple]=None

    