#MINICRYPTO 3.1:
#simply copy paste the required imports and the code, use as:		mc = minicrypto()  <-will return a minicrypto object
#contains: 
# -	RSA public key encryption algoritgm					mc.rsaKeys() -> generate keys,   mc.rsa() -> encryption and decryption
# -	CHA (cool hashing algorithm) 192bit hashing algorithm			mc.hash()
# -	CHA192 HMAC signature algorithm						mc.hmac()
# -	192bit ABS (authenticated block-stream) symmetric cipher		mc.encrypt(), mc.decrypt()
# -	generators of random bytes and bits					mc.randomBytes(), mc.randomBits
# -	byte encodings: utf8, base64, hexadecimal, binary and integers	mc.utf8ToBytes(), mc.bytesToUtf8 ...
# -	pkcs padding scheme, prime checkers and other cryptographic functions

import random, base64
from functools import reduce

class minicrypto:
	padBytes = lambda self, Bytes, blocksize: Bytes + ([blocksize - (len(Bytes) % blocksize) or blocksize] * (blocksize - (len(Bytes) % blocksize) or blocksize))
	unPadBytes = lambda self, Bytes: Bytes[0 : -Bytes[-1]]
	bytesToBin = lambda self, Bytes: "".join([("0000000" + bin(byte)[2:])[-8:] for byte in Bytes])
	binToBytes = lambda self, Bin: [int(Bin[i : (i + 8)], 2) for i in range(0, len(Bin), 8)]
	bytesToHex = lambda self, Bytes: "".join([("0" + hex(byte)[2:])[-2:] for byte in Bytes])
	hexToBytes = lambda self, Hex: [int(Hex[i:(i + 2)], 16) for i in range(0, len(Hex), 2)]
	bytesToUtf8 = lambda self, Bytes: bytes(Bytes).decode("utf-8")
	utf8ToBytes = lambda self, utf8: list(utf8.encode("utf-8"))
	bytesToBase64 = lambda self, Bytes: str(base64.b64encode(bytes(Bytes)))[2:-1]
	base64ToBytes = lambda self, Base64: list(base64.b64decode(Base64))
	bytesToInt = lambda self, Bytes: reduce(lambda num, byte: num | byte, [Bytes[::-1][idx] << (idx * 8) for idx in range(len(Bytes))], 0)
	intToBytes = lambda self, Int, minbytes = 0: [(Int >> ix) & 0xff for ix in range(0, max(Int.bit_length(), minbytes * 8), 8)][::-1]
	randomBytes = lambda self, length = 24: [random.randint(0, 255) for i in range(length)]
	hmac = lambda self, message, key, iv = ([0] * 24): self.hash((self.xorBlocks(key, [0xa5] * len(key))) + self.xorBlocks(self.hash(key + message), iv))
	byteRotLeft = lambda self, byte, shift: (byte << shift | byte >> (8 - shift)) & 0xff
	wordRotLeft = lambda self, word, shift: (word << shift | word >> (32 - shift)) & 0xffffffff
	wordCut = lambda self, word: word & 0xffffffff
	invert = lambda self, word: word ^ 0xffffffff
	xorBlocks = lambda self, block1, block2: [block1[idx] ^ block2[idx] for idx in range(len(block1))]
	increment = lambda self, counter: self.intToBytes((self.bytesToInt(counter) + 1) % (2 ** 24), len(counter))
	modInv = lambda self, int1, int2: pow(int1, -1, int2)
	randomBits = lambda self, leng: random.randint(0, (1 << (leng - 1)) | 1 | (1 << (leng - 1)) - 1)
	rsa = lambda self, msg, keypair: self.intToBytes(self.modPow(self.bytesToInt(msg), keypair[0], keypair[1]))
	def __init__(self):
		self.version = "3.1"
		self.prefix = [109, 105, 110, 105, 45, 51, 49, 95]
	def fermat(self, prime, iters = 32):
		for i in range(iters):
			rnd = self.randomBits(5 + random.randint(0, 10))
			if(self.modPow(rnd, prime - 1, prime) != 1): return False
		return True
	def rsaKeys(self, bits = 1024):
		mod, pubExp, privExp, x = self.makeKeys(self.findPrime(bits), self.findPrime(bits))
		return {"public": [pubExp, mod], "private": [privExp, mod]}
	def modPow(self, base, exp, mod):
		result = 1
		while exp > 0:
			if exp % 2 == 1: result = (result * base) % mod
			exp, base = exp >> 1, (base ** 2) % mod
		return result
	def gcd(self, a, b):
		if b > a: a, b = b, a
		while True:
			if(b == 0): return a
			a %= b
			if(a == 0): return b
			b %= a
	def millerRabin(self, num, iters = 16):
		k, n = 0, num - 1
		while n % 2 == 0: n, k = n >> 1, k + 1
		def trial(a):
			if pow(a, n, num) == 1: return False
			for ix in range(k):
				if pow(a, 2 ** ix * n, num) == num - 1: return False
			return True
		for i in range(iters):
			if trial(random.randrange(2, n - 1)): return False
		return True
	def makeKeys(self, prime1, prime2):
		N, phi = prime1 * prime2, (prime1 - 1) * (prime2 - 1)
		E, lnn = phi, phi.bit_length()
		while self.gcd(E, phi) != 1 or E > phi: E = self.randomBits(lnn - random.randint(4, lnn >> 2))
		D = self.modInv(E, phi)
		return N, E, D, phi
	def findPrime(self, bits):
		candidate = self.randomBits(bits)
		while (not self.millerRabin(candidate)) or (not self.fermat(candidate)): candidate = self.randomBits(bits)
		return candidate
	def hash(self, Bytes):
		prep, blocks = Bytes, []
		while len(prep) % 4 != 0: prep.append(0)
		words = [self.bytesToInt(prep[word : word + 4]) for word in range(0, len(prep), 4)] + [self.wordCut(len(Bytes))]
		while len(words) % 8 != 0: words.append(0)
		for idx in range(0, len(words), 8):
			chunk = words[idx: idx + 8]
			while len(chunk) < 56: chunk.append(self.wordRotLeft(self.wordRotLeft(chunk[-2], 1) ^ chunk[-4] ^ self.wordRotLeft(chunk[-5], 31) ^ chunk[-8], 1))
			blocks.append(chunk)
		a0, b0, c0, d0, e0, f0, salt = 0xbd173622, 0x96d8975c, 0x3a6d1a23, 0xe5843775, 0x29d2933f, 0x8d59a1df, 0
		for block in blocks:
			A, B, C, D, E, F = a0, b0, c0, d0, e0, f0
			for rnd in range(len(block)):
				if rnd % 6 == 0: temp = self.invert(C) & self.wordRotLeft(E | self.invert(A), 21)
				elif rnd % 6 == 1: temp = (A & B) | self.wordRotLeft(self.invert(E) & F, 5)
				elif rnd % 6 == 2: temp = B ^ self.wordRotLeft(F ^ D, 11) ^ self.wordRotLeft(A, 19)
				elif rnd % 6 == 3: temp = D ^ self.wordCut(self.wordRotLeft(B, 7) + self.wordCut(F + A))
				elif rnd % 6 == 4: temp = self.wordCut(E + self.wordRotLeft(C, 13)) ^ self.wordRotLeft(B, 16) ^ D
				else: temp = A ^ self.wordRotLeft(B, 26) ^ self.invert(C) ^ self.wordCut(E + F)
				salt ^= self.wordCut(F + [0xce864cf1, 0xf1de47b6, 0xa987042f, 0x7c02ad79, 0x04bb9692][rnd % 5])
				F, E, D, C, B, A = E, D, C ^ self.wordCut(A + B ^ D + (self.invert(C))), B ^ self.invert(F), salt ^ A, self.wordCut(block[rnd] + self.wordRotLeft(F, rnd % 32)) ^ temp
			a0, b0, c0, d0, e0, f0 = self.wordCut(a0 + A), self.wordCut(b0 + B), self.wordCut(c0 + C), self.wordCut(d0 + D), self.wordCut(e0 + E), self.wordCut(f0 + F)
		return self.intToBytes(a0) + self.intToBytes(b0) + self.intToBytes(c0) + self.intToBytes(d0) + self.intToBytes(e0) + self.intToBytes(f0)
	def permuteRow(self, row, itr = 1):
		result = row[0:4]
		for byte in range(1, 4): result[byte] = (result[byte] + result[byte - 1]) % 256
		result = self.intToBytes(self.wordRotLeft(self.bytesToInt(result) ^ 0xa987042f, (itr + 1) % 8), 4)[::-1]
		for byte in range(1, 4): result[byte] = result[byte] ^ self.byteRotLeft(result[byte - 1], 3)
		return result
	def permuteBlock(self, b, iters = 10):
		for i in range(iters):
			b = [b[21], b[18], b[7], b[0], b[4], b[1], b[22], b[11], b[8], b[5], b[2], b[15], b[12], b[9], b[6], b[19], b[16], b[13], b[10], b[23], b[20], b[17], b[14], b[3]]
			b = self.permuteRow(b[0:4], i) + self.permuteRow(b[4:8]) + self.permuteRow(b[8:12]) + self.permuteRow(b[12:16]) + self.permuteRow(b[16:20]) + self.permuteRow(b[20:24], i)
		return b
	def encrypt(self, message, key, iv = True):
		if iv == True: iv = self.randomBytes(24)
		elif iv == False: iv = [0] * 24
		assert len(iv) == 24 and len(key) == 24, "invalid key or iv provided"
		result, cntr = [], iv[0:]
		for idx in range(0, len(message), 24):
			result += self.xorBlocks(message[idx : idx + 24], self.permuteBlock(self.xorBlocks(key, self.permuteBlock(cntr, 6)), 12))
			cntr = self.increment(cntr)
		return self.prefix + iv + result + self.hmac(result, key, iv)
	def decrypt(self, message, key):
		header, iv, msg, signature = message[:len(self.prefix)], message[len(self.prefix) : len(self.prefix) + 24], message[len(self.prefix) + 24 : -24], message[-24:]
		assert len(iv) == 24 and len(key) == 24, "invalid key or iv provided"
		assert header == self.prefix, "invalid header or version of minicrypto"
		assert signature == self.hmac(msg, key, iv), "invalid signature"
		result, cntr = [], iv[0:]
		for idx in range(0, len(msg), 24):
			result += self.xorBlocks(msg[idx : idx + 24], self.permuteBlock(self.xorBlocks(key, self.permuteBlock(cntr, 6)), 12))
			cntr = self.increment(cntr)
		return result
