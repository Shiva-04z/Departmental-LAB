from fastapi import APIRouter
from models.schemas import CipherRequest
from logics import problem1

router = APIRouter(prefix="/caesar", tags=["Caesar Cipher"])

@router.post("/encrypt")
def caesar_encrypt(req: CipherRequest):
    encrypted_text = problem1.encrypt(req.text, req.shift)
    return {"encrypted_text": encrypted_text}

@router.post("/decrypt")
def caesar_decrypt(req: CipherRequest):
    decrypted_text = problem1.decrypt(req.text, req.shift)
    return {"decrypted_text": decrypted_text}
