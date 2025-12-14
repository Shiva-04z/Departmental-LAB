from fastapi import APIRouter
from models.schemas import AESRequest
from logics import problem5

router = APIRouter(prefix="/AES", tags =["AES"])

@router.post('/encrypt')
def encrypt_AES(req: AESRequest):
    aes = problem5.AES()
    ciphertext, encrypted_blocks = problem5.encrypt_text(aes, req.text)
    return {"encrypted Text": ciphertext,"encrypted_blocks": encrypted_blocks}


@router.post('/decrypt')
def encrypt_AES(req: AESRequest):
    aes = problem5.AES()
    plain_text = problem5.decrypt_text(aes, req.text, req.encrypted_blocks)
    return {"decrypted Text": plain_text}

