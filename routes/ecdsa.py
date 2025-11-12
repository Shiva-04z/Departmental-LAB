from fastapi import APIRouter
import binascii
from models.schemas import ECDSARequest
from logics import problem10

router = APIRouter(prefix = "/ecdsa", tags = ["ECDSA"])


@router.get("/generate")
def generate():
    ecdsa = problem10.ECDSA()
    privateKey,publicKey = ecdsa.generate_key_pair()
    return{"Private": privateKey,"Public": publicKey}

@router.post("/sign")
def sign(req: ECDSARequest):
        ecdsa = problem10.ECDSA()
        sign = ecdsa.sign_message(req.text,req.private)
        return{"sign": sign}


@router.post("/verify")
def sign(req: ECDSARequest):
        ecdsa = problem10.ECDSA()
        sign = ecdsa.verify_signature(req.text,req.sign,req.key)
        return{"Verified": sign}

    