#!/usr/bin/env sage

from sage.all import *
import struct
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5
from threading import Thread

# Our "MPI" format consists of 4-byte integer length l followed by l bytes of binary key
def int_to_mpi(z):
    s = int_to_binary(z)
    return struct.pack('I',len(s))+s

# Horrible hack to get binary representation of arbitrary-length long int
def int_to_binary(z):
    s = ("%x"%z); s = (('0'*(len(s)%2))+s).decode('hex')
    return s

def bits_to_mpi(s):
    return struct.pack('I',len(s))+s

encrypt_header = '-----BEGIN PRETTY BAD ENCRYPTED MESSAGE-----\n'
encrypt_footer = '-----END PRETTY BAD ENCRYPTED MESSAGE-----\n'

# PKCS 7 pad message.
def pad(s,blocksize=AES.block_size):
    n = blocksize-(len(s)%blocksize)
    return s+chr(n)*n

# Encrypt string s using RSA encryption with AES in CBC mode.
# Generate a 256-bit symmetric key, encrypt it using RSA with PKCS1v1.5 padding, and prepend the MPI-encoded RSA ciphertext to the AES-encrypted ciphertext of the message.
def encrypt(rsakey,s):
    aeskey = Random.new().read(32)

    pkcs = PKCS1_v1_5.new(rsakey)
    output = bits_to_mpi(pkcs.encrypt(aeskey))
    
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aeskey, AES.MODE_CBC, iv)

    output += iv + cipher.encrypt(pad(s))
    return encrypt_header + output.encode('base64') + encrypt_footer

def mul(a, b, ls, idx):
	ls[idx] = a*b

def get_mod(a, b, tmp):
	tmp.append(Integer(mod(a,(b*b))))
    
def product_tree(mods):

	tree = [mods]
	level = 1
	while(len(mods) > 1):
		print "Level: " + str(level)
		n = len(mods)/2
		intermediate_lvl = [1]*((len(mods) + 1)/2)
		threads = []
		for i in range(0, n):
			t = Thread(target=mul, args = (mods[2 * i], mods[(2 * i) + 1], intermediate_lvl, i))
			t.start()
			threads.append(t);
		for i in range(len(threads)):
			threads[i].join()
		tree.append(intermediate_lvl);
		level = level + 1
		mods = intermediate_lvl[:]
	return tree

def parse_mpi(s,index):
    length = struct.unpack('<I',s[index:index+4 ])[0]
    z = Integer(s[index+4 :index+4 +length].encode('hex'),16 )
    return z, index+4 +length

def get_decryption(candidates):
	ct = open('ciphertext').read()
	ct = re.search(encrypt_header+"(.*)"+encrypt_footer,ct,flags=re.DOTALL).group(1).decode('base64')
	index = 0 
	dsize = SHA.digest_size
	sentinel = Random.new().read(15+dsize)
	aes_key_enc, index = parse_mpi(ct,index)
	iv = ct[index:index + 16]
	s = ct[index + 16 : ]
	e = 65537
	ls = []
	
	# candidates[1] gives an aes key with improper length
	# Therefore we only use candidates[0]
	pair = candidates[0]
	p = pair[0]
	q = pair[1]
	phi_n = Integer((p-1)*(q-1))
	n = (p*q)
	d,u,v = xgcd(e,phi_n)
	key_params = (long(n), long(e), long(u), long(p), long(q))
	key = RSA.construct(key_params)
	pkcs = PKCS1_v1_5.new(key)
	aeskey = pkcs.decrypt(int_to_binary(aes_key_enc), sentinel)
	cipher = AES.new(aeskey, AES.MODE_CBC, iv)
	output = cipher.decrypt(pad(s))
	ls.append(output)
	return ls



def remainder_tree(prod_tree, mods):
	N = len(prod_tree)
	idx = N - 2
	rem_tree = [prod_tree[N - 1][0]]
	while(idx > -1):
		print "Level: " + str(idx)
		tmp = []
		threads = []
		for i in range(0, len(prod_tree[idx])):
			t = Thread(target=get_mod, args = (rem_tree[i/2], (prod_tree[idx][i]), tmp))
			t.start()
			threads.append(t);
		for i in range(len(threads)):
			threads[i].join()

		rem_tree = tmp[:]
		idx = idx - 1
	for i in range(len(rem_tree)):
		if(mod(rem_tree[i], mods[i]) == 0):
			x = Integer(rem_tree[i]/mods[i])
		else:
			x = 1
		rem_tree[i] = gcd(x, prod_tree[0][i])
	return rem_tree

if __name__=='__main__':
    # Store all the moduli in the list mods as Integer
    mods = open('MODS.txt').read().splitlines()
    for i in range(0, len(mods)):
        mods[i] = Integer(int(mods[i], 16))

    # Compute the product tree
    prod_tree = product_tree(mods)
    print "Product Tree constructed...\n"

    # Compute the remainder tree
    rem_tree = remainder_tree(prod_tree, mods)
    print "Candidates obtained...\n"

    # Check if any entries in the final level match the corresponding moduli
    # If so, make it 1 (for readability)
    for i in range(min(len(mods), len(rem_tree))):
    	if rem_tree[i] == mods[i]:
    		rem_tree[i] = 1

    # Store the moduli candidates in candidates
    candidates = []
    for i in range(min(len(mods), len(rem_tree))):
    	if(rem_tree[i] != 1):
    		candidates.append([rem_tree[i], mods[i]/rem_tree[i]])
    out = get_decryption(candidates)
    for i in range(len(out)):
		f = open('decrypted','w')
		f.write(out[i])
		f.close()
