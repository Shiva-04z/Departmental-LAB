from fastapi import APIRouter
import binascii
from models.schemas import DESRequest
from logics import problem4

router = APIRouter(prefix="/DES", tags =["DES"])

@router.post("/encrypt")
def des_encrypt(req:DESRequest):
    DES = problem4.DES(req.key)
    cipher_text = DES.encrypt(req.text)
    encrypted_text = binascii.hexlify(cipher_text).decode()
    return {"encrypted_text": encrypted_text}


@router.post("/decrypt")
def des_encrypt(req:DESRequest):
    DES = problem4.DES(req.key)
    ciphertext = binascii.unhexlify(req.text)
    decrypted_text = DES.decrypt(ciphertext)
    return {"decrypted_text": decrypted_text}