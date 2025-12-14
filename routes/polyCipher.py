from fastapi import APIRouter
from logics import problem2
from models.schemas import PolyRequest

router = APIRouter(prefix ="/poly",tags =["Poly Cipher"])



@router.post("/encrypt")
def caesar_encrypt(req: PolyRequest):
    encrypted_text = problem2.encrypt(req.text, req.key)
    return {"encrypted_text": encrypted_text}

@router.post("/decrypt")
def caesar_decrypt(req: PolyRequest):
    decrypted_text = problem2.decrypt(req.text, req.key)
    return {"decrypted_text": decrypted_text}