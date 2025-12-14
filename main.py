from fastapi import FastAPI
from pydantic import BaseModel

from routes import health, caesarCipher , polyCipher, playfairCipher, des, aes, rc4 ,rsa, hashes, rsa_verifier, ecdsa


app = FastAPI()



app.include_router(caesarCipher.router)
app.include_router(polyCipher.router)
app.include_router(playfairCipher.router)
app.include_router(des.router)
app.include_router(aes.router)
app.include_router(rc4.router)
app.include_router(rsa.router)
app.include_router(hashes.router)
app.include_router(rsa_verifier.router)
app.include_router(ecdsa.router)
app.include_router(health.router)

