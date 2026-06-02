import os

def rotr(x, n): #Used ascon.py from GitHub as a reference
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF
def permutation(rounds,state): #Used ascon.py from GitHub and the slides as a reference
    x0,x1,x2,x3,x4=state
    ROUND_CONSTANTS = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    for r in range(12-rounds,12): #Max permutations is 12 rounds
        # Pc
        x2^=ROUND_CONSTANTS[r]
        
        # Ps
        x0^=x4
        x4^=x3
        x2^=x1
        
        MASK=0xFFFFFFFFFFFFFFFF
        t0=(x0^MASK)&x1
        t1=(x1^MASK)&x2
        t2=(x2^MASK)&x3
        t3=(x3^MASK)&x4
        t4=(x4^MASK)&x0
        
        x0^=t1
        x1^=t2
        x2^=t3
        x3^=t4
        x4^=t0
        
        x1^=x0
        x0^=x4
        x3^=x2
        x2^=0xFFFFFFFFFFFFFFFF
        
        #Pl
        x0^=rotr(x0,19)^rotr(x0,28)
        x1^=rotr(x1,61)^rotr(x1,39)
        x2^=rotr(x2,1)^rotr(x2,6)
        x3^=rotr(x3,10)^rotr(x3,17)
        x4^=rotr(x4,7)^rotr(x4,41)
    return [x0,x1,x2,x3,x4]



def initialization_phase(k,r,a,b,key,nonce):
    IV = (
        (k << 56) |
        (r << 48) |
        (a << 40) |
        (b << 32)
    )
    key = int.from_bytes(key, "big")
    nonce = int.from_bytes(nonce, "big")
    Internal_State = (
        (IV << 256) |
        (key << 128) |
        nonce
    )
    x0 = (Internal_State >> 256) & 0xFFFFFFFFFFFFFFFF
    x1 = (Internal_State >> 192) & 0xFFFFFFFFFFFFFFFF
    x2 = (Internal_State >> 128) & 0xFFFFFFFFFFFFFFFF
    x3 = (Internal_State >> 64)  & 0xFFFFFFFFFFFFFFFF
    x4 = Internal_State & 0xFFFFFFFFFFFFFFFF
    state=permutation(a,[x0,x1,x2,x3,x4])
    state[3]^=x1
    state[4]^=x2
    return state
    
    
    
def associated_phase(state,associated_data,b):
    blocks=[]
    
    associated_data+=b'\x01' #ASCON padding rule
    while len(associated_data)%8!=0:
        associated_data+=b'\x00'
    
    for i in range(0,len(associated_data),8): #Each block 8 bytes == 64 bits
        block=int.from_bytes(associated_data[i:i+8],"big")
        blocks.append(block)
        
    for block in blocks:
        state[0]^=block #r = 64 bits and each block is 64 bits so state[0] can be taken all for the XOR process
        state=permutation(b,state)
        
    state[4]^=1
    return state



def plaintext_phase(state, plaintext, b):
    ciphertext = b""
    blocks = []
    
    original_len = len(plaintext)
    
    plaintext += b'\x01'
    while len(plaintext) % 8 != 0:
        plaintext += b'\x00'
        
    for i in range(0, len(plaintext), 8):
        block = int.from_bytes(plaintext[i:i+8], "big")
        blocks.append(block)
    
    for i in range(len(blocks)):
        state[0] ^= blocks[i]
        cipherblock = state[0]
        
        if i == len(blocks) - 1:
            rem = original_len % 8
            ciphertext += cipherblock.to_bytes(8, "big")[:rem if rem != 0 else 8]
        else:
            ciphertext += cipherblock.to_bytes(8, "big")
            state = permutation(b, state)
            
    return state, ciphertext



def ciphertext_phase(state,ciphertext,b):
    plaintext=b""
    blocks=[]
    
    for i in range(0,len(ciphertext),8):
        block=int.from_bytes(ciphertext[i:i+8],"big")
        blocks.append(block)
    
    for i in range(len(blocks)):
        cipherblock=blocks[i]
        plainblock=state[0]^cipherblock
        plaintext+=plainblock.to_bytes(8,"big")
        state[0]=cipherblock
        
        if i!=len(blocks)-1:
            state = permutation(b,state)
    return state,plaintext



def finalization_phase(state,key,a):
    key=int.from_bytes(key,"big")
    k0=(key>>64)&0xFFFFFFFFFFFFFFFF
    k1=key&0xFFFFFFFFFFFFFFFF
    
    state[1]^=k0
    state[2]^=k1
    state=permutation(a,state)
    
    state[3]^=k0
    state[4]^=k1
    
    tag=(state[3].to_bytes(8,"big")+state[4].to_bytes(8,"big"))
    
    return tag



def encrypt(key,nonce,associated_data,plaintext):
    k=128
    r=64
    a=12
    b=6
    state=initialization_phase(k,r,a,b,key,nonce)
    state=associated_phase(state,associated_data,b)
    state,ciphertext=plaintext_phase(state,plaintext,b)
    tag=finalization_phase(state,key,a)
    return ciphertext,tag

    
    
def decrypt(key,nonce,associated_data,ciphertext,tag):
    k=128
    r=64
    a=12
    b=6
    state=initialization_phase(k,r,a,b,key,nonce)
    state=associated_phase(state,associated_data,b)
    state,plaintext=ciphertext_phase(state,ciphertext,b)
    check_tag=finalization_phase(state,key,a)
    
    if check_tag==tag:
        return plaintext
    else:
        return None
    
    

def ascon_hash(message):
    IV=0x00400c0000000100
    state=[IV,0,0,0,0]
    state=permutation(12,state)
    
    message+=b'\x01'
    while len(message)%8!=0:
        message+=b'\x00'
    
    for i in range(0,len(message),8):
        block=int.from_bytes(message[i:i+8],"big")
        state[0]^=block
        state=permutation(12,state)
        
    output=b""
    for i in range(4):
        output+=state[0].to_bytes(8,"big")
        if i!=3:
            state=permutation(12,state)
            
    return output

key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
nonce = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
associated=b"ascon"
plaintext=b"hardware security"
ciphertext,tag=encrypt(key,nonce,associated,plaintext)
pt = decrypt(key,nonce,b"ascon",ciphertext,tag)

print(f'Ciphertext: {ciphertext.hex()}')
print(f'Tag: {tag.hex()}')
print(f'Plaintext: {pt}')
digest=ascon_hash(plaintext)
print(f'Hash: {digest.hex()}')
