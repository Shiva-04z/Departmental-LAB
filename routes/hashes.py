from fastapi import APIRouter
from logics import problem8
from models.schemas import HashRequest

router = APIRouter(prefix = "/hashes", tags = ["Hash Verifier"])

@router.post('/getHash')
def get_hash(req: HashRequest):
    Hashes = problem8.HashGenerator()
    hash =Hashes.generate_all_hashes(req.text)
    return hash

@router.post('/verify')
def get_hash(req: HashRequest):
    Hashes = problem8.HashGenerator()
    hash =Hashes.verify_hash(req.text,req.hash,req.algo,)
    return {"Verifucation":"Successful" if hash else "Failed"}