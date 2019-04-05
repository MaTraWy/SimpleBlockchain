from Crypto.Hash import SHA256,RIPEMD
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
#key = RSA.generate(2048)
#f = open('mahmoud.pem','w')
#f.write(key.exportKey('PEM').decode())
#f.write('\n'+key.publickey().exportKey('PEM').decode())
#f.close()

f = open('mahmoud.pem','r')
key = RSA.importKey(f.read())
f.close()
print(len(RIPEMD.new("loled").hexdigest()))
privateKey = key.exportKey()
publicKey = key.publickey().exportKey()
lol = (privateKey[32::])[:-30]
loled = (publicKey[27::])[:-25]
print(loled)
print(publicKey)
message = "Hello World"
h = SHA256.new(message.encode())
privKey = RSA.importKey(privateKey)
singer = PKCS1_v1_5.new(privKey)
signature = singer.sign(h)
print(signature.hex())

message = "Hello World"
h = SHA256.new(message.encode())
lol = privKey.encrypt(h.digest(),256)
print(lol[0].hex())
singer = PKCS1_v1_5.new(RSA.importKey(publicKey))
if singer.verify(h,signature):
    print("True")
