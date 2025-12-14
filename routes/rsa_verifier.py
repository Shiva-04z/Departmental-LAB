from fastapi import APIRouter
from models.schemas import RSAVerifyRequest
from logics import problem7 , problem9


router = APIRouter(prefix="/RSAVerifier", tags =["RSA Verifier"])


@router.get('/generate')
def get_Keys():
    rsa = problem7.RSA(2048)
    publickey,privatekey = rsa.generate_key_pair()
    return {"public key": publickey,"private key" : privatekey}

@router.post('/generateSign')
def get_Sign(req : RSAVerifyRequest):
    text, sign = problem9.generate_Signature(req.text,req.key)
    return {"text" : text, "sign": sign}

@router.post('/verify')
def verify(req:RSAVerifyRequest):
    verification = problem9.verify_Signature(req.text,req.sign, req.key)
    return {"Verification" : verification}



