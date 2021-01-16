# mini-python
currenctly contains:
- minicrypto.py

## minicrypto
Tired of having to import ciphers that are well known, proven and fast?  
Try minicrypto! a compact multi-language custom opensource cryptolibrary that you can copypaste straight into your code and use it straight away.  
`mc = minicrypto()`
> while ciphers used are not breakable, it should be mentioned that only well-known and proven ciphers should be used to protect important data, and python itself isnt very fast and might be vulnerable to very advanced types of attacks on data in memory.  

But this cryptolibrary is, i think, a really cool compilation of cryptofunctions that are self-made, yet very strong. It is a result of my learning in the field of crpythography.
  
currently contains:
- RSA public key encryption algoritgm
- CHA (cool hashing algorithm) 192bit hashing algorithm
- CHA192 HMAC signature algorithm
- 192bit MSP (my SP) symmetric cipher in HAC (hash autenticated counter) mode
- generators of random bytes and bits
- byte encodings: utf8, base64, hexadecimal, binary and integers
- pkcs padding scheme, prime checkers and other cryptographic functions  
  
the cryptographic functions operate on bytearrays, that means lists of bytes - positive integers 0 - 255.
Therefore, the data must be provided as bytes, use the encoding functions to convert data to bytes and to then convert bytes back to strings.
```python
data = "a string"
bytearray = mc.utf8ToBytes(data)
hexstring = mc.bytesToHex(bytearray)
```
wanna hash a string or make a key for encryption?  
```python
key = mc.bytesToHex(mc.hash(mc.utf8ToBytes("a strong key or a string to be hashed")))
```   
wanna encrypt a string with a password?
```python
data = mc.utf8ToBytes("a string to be encrypted")
encrypted = mc.bytesToBase64(mc.encrypt(data, key))
```
wanna encrypt a file with a custom iv counter?
```python
source = open("data.txt", "rb") # "rb" - we are reading in bytes
iv = mc.randomBytes(24)
print("iv used during encryption:", iv)
encrypted = mc.encrypt(list(f.read()), key) #list(f.read()) we are converting the bytes object to a simple list of bytes
source.close()
change = open("data.txt", "wb")
change.write(encrypted)
```  
wanna simply do an hmac of some data?
```python
source = open("data.txt", "rb")
signature = mc.hmac(list(source.read()), key) #you could also pass the iv as another argument, if you dont, it will be all zeros
print("hmac:", mc.bytesToHex(signature))
```
