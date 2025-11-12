from fastapi import APIRouter
from models.schemas import RSARequest
from logics import problem7


router = APIRouter(prefix="/RSA", tags =["RSA"])

@router.get('/generate')
def get_Keys():
    rsa = problem7.RSA(2048)
    publickey,privatekey = rsa.generate_key_pair()
    return {"public key": publickey,"private key" : privatekey}


@router.post('/encrypt')
def encrypt(req: RSARequest):
    rsa = problem7.RSA(2048)
    encrypted_text= rsa.encrypt(req.text, req.key)
    encrypted_text= problem7.bytes_to_base64(encrypted_text)
    return {"encrypted_text": encrypted_text}



@router.post('/decrypt')
def encrypt(req: RSARequest):
    rsa = problem7.RSA(2048)
    text = problem7.base64_to_bytes(req.text)
    decrypted_text= rsa.decrypt(text, req.key)
    return {"decrypted_text": decrypted_text}