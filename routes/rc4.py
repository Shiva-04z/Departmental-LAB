from fastapi import APIRouter
from models.schemas import RC4Request
from logics import problem6


router = APIRouter(prefix="/RC4", tags = ["RC4 cipher"])

@router.post("/encrypt")
def encrypt(req: RC4Request):
    RC4 = problem6.RC4(req.key)
    encrypted_text = RC4.encrypt(req.text)
    encrypted_text = problem6.bytes_to_hex(encrypted_text)
    return {"encrypted_text" : encrypted_text}


@router.post("/decrypt")
def encrypt(req: RC4Request):
    RC4 = problem6.RC4(req.key)
    text = problem6.hex_to_bytes(req.text)
    decrypted_text = RC4.decrypt(text)
    return {"decrypted_text" : decrypted_text}