import json
import hashlib
from Crypto.Hash import SHA256

# a Python object (dict):
x = {
  "name": "John",
  "age": 30,
  "city": "New York"
}
LL = 'MEW'
KK = "00baf6626abc2df808da36a518c69f09b0d2ed0a79421ccfde4f559d2e42128b"
KL = "00baf6626abc2df808da36a518c69f09b0d2ed0a79421ccfde4f559d2e42128b"
print(KK[:2])
l = SHA256.new("omg".encode()).digest()
ll= SHA256.new(l).hexdigest()
o = SHA256.new("omg".encode()).hexdigest()
print(l.hex(),'\n',o)
oo = SHA256.new(bytes.fromhex(o)).hexdigest()
print(oo,'\n',ll)
print(bytes.fromhex(KK)+bytes.fromhex(KL))
inte = ['ss',65]
print(''.join(map(str,inte)))
m = hashlib.md5()
m.update("lol".encode())
m.update(str(5).encode())
#print(m.hexdigest())
#print(hashlib.md5("lol5".encode()).hexdigest())
# convert into JSON:
y = json.dumps(x).encode(encoding="utf8")

l = (1,2,"ho")
l = json.dumps(l).encode(encoding="utf8")
print(l[0])
# the result is a JSON string:
#print(hashlib.sha256(l).hexdigest())
