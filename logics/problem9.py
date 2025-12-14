from logics import problem8, problem7


def generate_Signature(text, publicKey):
    rsa = problem7.RSA(2048)
    Hashgenerator = problem8.HashGenerator()
    signature = Hashgenerator.generate_hash(text,'sha256')
    text = rsa.encrypt(text,publicKey)
    text = problem7.bytes_to_base64(text)
    return text,signature

def verify_Signature(text, signature,privateKey):
    rsa = problem7.RSA(2048)
    text = problem7.base64_to_bytes(text)
    text = rsa.decrypt(text,privateKey)
    Hashgenerator = problem8.HashGenerator()
    newsignature = Hashgenerator.generate_hash(text,'sha256')
    return newsignature==signature



def main():
    text= input("Enter the text : \n ")
    rsa = problem7.RSA(2048)
    publicKey, privateKey = rsa.generate_key_pair()
    text,signature = generate_Signature(text,publicKey)
    print(f"text :{text}, signature : {signature}")

    verification = verify_Signature(text,signature,privateKey)
    print(f"Verification Status: {verification}")


