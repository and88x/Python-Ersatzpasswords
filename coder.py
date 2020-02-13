from random import sample, randrange, choice
import hashlib, binascii

######################### Functions #########################
def bits2str(b):
	""" Receive a binary string and return the equivalents characters
		Example:
		>>> bits2str('0110100001100101011011000110110001101111')
		'hello'		
		"""
	return ''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(b)]*8))

def str2bits(string):
	""" Receive a string and return the binary string
		Example:
		>>> str2bits('hello')
		'0110100001100101011011000110110001101111'
	"""
	return ''.join(format(ord(x), 'b') for x in string)	

def int2bits(s):
	""" Return the number in base 2
		Example:
		>>> int2bits(15)
		1111
	"""
	return '{0:b}'.format(s)	

def str2bytes(s):
	""" Return the equivalent string in bytes
		Example:
		>>> str2bytes("hello")
		b'hello'
	"""
	return bytes(s, 'utf-8')

def bytes2str(s):
	""" Return the equivalent string in bytes
		Example:
		>>> bytes2str(b'hello')
		"hello"
	"""
	return (s).decode("utf-8")

def Hash_sha224(h):
	# the hashlib works with bytes and we need to transform the
	# parameters into bytes format
	h1 = str2bytes(h)
	return str2bytes(hashlib.sha256(h1).hexdigest())

def Hash_sha256(p, s):
	return bytes2str(binascii.hexlify(hashlib.pbkdf2_hmac('sha256', p, s, 10000)))

def TPR(Password1):
	""" This function compute the ErsatzPasswords with the method of 
		Total Password Replacement
	"""
	global alphabet_L 
	global alphabet_D 
	global alphabet_Ch  
	global size_L 
	global size_D 
	global size_Ch 
	global mix_alphabet_L 
	global mix_alphabet_D 
	global ix_alphabet_Ch
	size_pass1 = len(Password1)

	ersatzpassword1 = ""
	#print(alphabet_L, alphabet_D, alphabet_Ch)
	#print(''.join(mix_alphabet_L), ''.join(mix_alphabet_D), ''.join(mix_alphabet_Ch))
	#to map the equivalent character on the new alphabets
	for x in range(0,size_pass1):
		l1 = alphabet_L.find(Password1[x])
		l2 = alphabet_D.find(Password1[x])
		l3 = alphabet_Ch.find(Password1[x])
		if l1 >= 0:
			ersatzpassword1 += mix_alphabet_L[l1]
		if l2 >= 0:
			ersatzpassword1 += mix_alphabet_D[l2]
		if l3 >= 0:
			ersatzpassword1 += mix_alphabet_Ch[l3]	

	#to choose a random number for shift the encrypted password
	global rand_shift1
	#next shift to rigth the ersatzpassword rand_shift times
	ersatzpassword1 = ersatzpassword1[-rand_shift1:]+ersatzpassword1[0:-rand_shift1]	
	return ersatzpassword1

def GBM(Password2):
	""" This function compute the ErsatzPasswords with 
		Grammar-Based Methods
	"""
	alphabet_L 	= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphabet_D 	= "0123456789"
	alphabet_Ch = "<=>@#%&+-_$"

	size_pass2	= len(Password2)
	size_L 		= len(alphabet_L)
	size_D 		= len(alphabet_D)
	size_Ch 	= len(alphabet_Ch)

	counter	    = 0
	tokens	    = [""]

	# to inicialiciate the flag
	if alphabet_L.find(Password2[0]) >= 0: prev_flag = 1
	if alphabet_D.find(Password2[0]) >= 0: prev_flag = 2
	if alphabet_Ch.find(Password2[0]) >= 0: prev_flag = 3
	flag = prev_flag

	# if we have a character change (letters, digits or special characters) 
	# the character is saved in a new token, it's when flag != prev_flag
	for x in range(0,size_pass2):
		if alphabet_L.find(Password2[x]) >= 0:
			flag = 1
			if flag != prev_flag: 
				counter += 1
				tokens.append("")
			tokens[counter] += Password2[x]
		if alphabet_D.find(Password2[x]) >= 0:
			flag = 2
			if flag != prev_flag: 
				counter += 1
				tokens.append("")
			tokens[counter] += Password2[x]
		if alphabet_Ch.find(Password2[x]) >= 0:
			flag = 3
			if flag != prev_flag: 
				counter += 1
				tokens.append("")
			tokens[counter] += Password2[x]
		prev_flag = flag

	# now, we need to create a dictionary with the tokens as keys
	# the dictionary have words with the same type and length that the tokens
	global dictionary
	size_tokens = len(tokens)
	global flag4GBM
	if flag4GBM == 0:
		dictionary = {}
		for x in range(0,size_tokens):
			p = ""
			if alphabet_L.find(tokens[x][0]) >= 0:	
				p = p.join([choice(alphabet_L) for i in range(len(tokens[x]))])
			if alphabet_D.find(tokens[x][0]) >= 0:	
				p = p.join([choice(alphabet_D) for i in range(len(tokens[x]))])
			if alphabet_Ch.find(tokens[x][0]) >= 0:	
				p = p.join([choice(alphabet_Ch) for i in range(len(tokens[x]))])
			if tokens[x] not in dictionary:
				dictionary[tokens[x]] = p

	ersatzpassword2 = ""
	rand_shift2		= 0

	# finally we assemble the ersatzpassword using the dictionary
	for x in range(0,size_tokens):
		# try sentence is needed because for a bad password the token
		# will not be in the dictionary
		try:	
			ersatzpassword2 += dictionary[tokens[x]]
		except Exception as e:
			pass
	return ersatzpassword2

def salt(Password1, User1, ersatzpassword1):
	Password1_bit = str2bits(Password1)
	User1_bit	  = str2bits(User1)
	ersatzpassword1_bit = str2bits(ersatzpassword1)
	s1 = int2bits(int(Password1_bit,2) | int(User1_bit,2)) 
	y1 = str2bits(bytes2str(Hash_sha224(bits2str(s1))))
	salt1 = str2bytes(bits2str(int2bits(int(y1,2) ^ int(ersatzpassword1_bit,2))))

	return salt1

#-----------------------------------------------------------------------------
#-------------------------- MAIN PROGRAM -------------------------------------
#-----------------------------------------------------------------------------

#-------------------------- Parameters ---------------------------------------
User1 		= "Android1"
User2 		= "Android2"
Password1 	= "12345"
Password2 	= "S3cure_p@$$_188"

global alphabet_L 
global alphabet_D 
global alphabet_Ch 
global size_pass1 
global size_L 
global size_D 
global size_Ch 
global mix_alphabet_L 
global mix_alphabet_D 
global ix_alphabet_Ch
global flag4GBM

flag4GBM = 0

alphabet_L 	= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
alphabet_D 	= "0123456789"
alphabet_Ch = "<=>@#%&+-_$"

size_pass1	= len(Password1)
size_L 		= len(alphabet_L)
size_D 		= len(alphabet_D)
size_Ch 	= len(alphabet_Ch)
#create a mixed version of the alphabets
mix_alphabet_L  = sample(alphabet_L, size_L)
mix_alphabet_D  = sample(alphabet_D, size_D)
mix_alphabet_Ch = sample(alphabet_Ch, size_Ch)

global rand_shift1
rand_shift1 = randrange(size_pass1)
global rand_shift2
rand_shift2 = 0

#-----------------------------------------------------------------------------
#-------------------------- Total Password Replacement -----------------------
#-----------------------------------------------------------------------------
ersatzpassword1 = TPR(Password1)

#-----------------------------------------------------------------------------
#-------------------------- Grammar-Based Methods ----------------------------
#-----------------------------------------------------------------------------
ersatzpassword2 = GBM(Password2)
flag4GBM = 1

#-----------------------------------------------------------------------------
#-------------------------- Encoder ------------------------------------------
#-----------------------------------------------------------------------------
# Next, I use the Python hashlib for to do the hash:
# https://docs.python.org/3/library/hashlib.html
h1 = Hash_sha224(ersatzpassword1)
h2 = Hash_sha224(ersatzpassword2)

salt1 =  salt(Password1, User1, ersatzpassword1)
salt2 =  salt(Password2, User2, ersatzpassword2)

final_ersatzpassword1 = Hash_sha256(h1, salt1)
final_ersatzpassword2 = Hash_sha256(h2, salt2)

salt2 = bytes2str(salt2)		
salt1 = bytes2str(salt1)

# I create a dictionary with the Users and the passwords for the validation
login = {}
login[User1] = final_ersatzpassword1
login[User2] = final_ersatzpassword2
#-----------------------------------------------------------------------------
#-------------------------- Create the password file -------------------------
#-----------------------------------------------------------------------------

# I save the users, hashed password, salt and the number of shift 
#file = open("testfile.txt","w") 
### 
#file.write(User1+":"+final_ersatzpassword1+":"+salt1+":"+str(rand_shift1)+"\n") 
#file.write(User2+":"+final_ersatzpassword2+":"+salt2+":"+str(rand_shift2)+"\n") 

#-----------------------------------------------------------------------------
#-------------------------- login validation ---------------------------------
#-----------------------------------------------------------------------------
print("Summary")
print("1.1.Total Password Replacement")
print("Password1:        ", Password1)
print("Erzatzpassword1:  ", ersatzpassword1)
print()
print("1.2.Grammar-Based Methods")
print("Password2:        ", Password2)
print("Erzatzpassword2:  ", ersatzpassword2)
print()
print("2.1.New hash and salt")
print("hash1: ", h1)
print("salt1: ", salt1)
print()
print("hash2: ", h2)
print("salt2: ", salt2)
print()
print("3.- Final hashed ersatzpassword")
print("1.- ", final_ersatzpassword1)
print("2.- ", final_ersatzpassword2)
print()
User4test		 = "Android1"
Password4test 	 = "S3cure_p@$$_155"
print("4.- Test")
print("User4test:     ", User4test)
print("Password4test: ", Password4test)

#Password4test 	 = "canada"

ersatzpassword4test = TPR(Password4test)
h4test = Hash_sha224(ersatzpassword4test)
salt4test =  salt(Password4test, User4test, ersatzpassword4test)
final_ersatzpassword4test = Hash_sha256(h4test, salt4test)

if User4test not in login:
	print("The User is incorrect")
else:
	if login[User4test] == final_ersatzpassword4test:
		print("Welcome "+User4test)
	else:
		if Password4test == login[User4test]:
			print("Malicious Login")
		else:
			print("The Passwor is incorrect")