from fastapi import APIRouter
from logics import problem3
from models.schemas import PlayFairRequest

router = APIRouter(prefix = "/playFair", tags = ["PlayFair Cipher"])

@router.post("/encrypt")
def playfair_encrypt(req: PlayFairRequest):
    encrypted_text = problem3.encrypt(req.text,req.key)
    return {"encrypted_text": encrypted_text}

@router.post("/decrypt")
def playfair_encrypt(req: PlayFairRequest):
    decrypted_text = problem3.decrypt(req.text,req.key)
    return {"decrypted_text": decrypted_text}