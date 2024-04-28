"""
#####, April 2024
Secure File Transfer with RSA and Hashing in Python
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
from os import path

"""
1.  RSA Key Generation
"""
class User():
	def __init__(self):
		self.PrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		self.PublicKey = self.PrivateKey.public_key()
"""
2.  RSA File Encryption
"""
def write_to_file(parts_data, file_path):
	with open(file_path, 'w') as file:
		file.write(parts_data)

def file_encrypt(file_path, recipient):
	try:
		with open(file_path,'rb') as file:
			data = file.read()
		data = [(data[i:i+200]) for i in range(0, len(data), 200)]
		encrypted_data=[]
		for piece in data:
			encrypted_piece = recipient.PublicKey.encrypt(
							    piece,
							    padding.PKCS1v15())
			encrypted_data.append(encrypted_piece)
		encrypted_data = ascii(encrypted_data)
		new_file_path = 'Encrypted_Files/' + path.basename(file_path)
		write_to_file(encrypted_data, new_file_path)
		print(f"File Successfully Encrypted: [{new_file_path}]. \n")
	except Exception as ERROR:
		print(f"Error! Encryption for {file_path} has failed. \n\t {ERROR.__class__.__name__}\n")
"""
3.  RSA File Decryption:
"""
def file_decrypt(file_path, recipient):
	#try:
		with open(file_path, 'rb') as file:
			data = file.read()
		data = eval(data)
		decrypted_data=[]
		for encrypted_piece in data:
			piece = recipient.PrivateKey.decrypt(
							    encrypted_piece,
							    padding.PKCS1v15())
			decrypted_data+=piece
		new_file_path = 'Decrypted_Files/' + path.basename(file_path)
		decrypted_data = bytes(decrypted_data)
		print(decrypted_data[0:10])
		with open(new_file_path, 'wb') as file:
			file.write(decrypted_data)
		print(f"File Successfully Decrypted: [{new_file_path}]. \n")
	#except Exception as ERROR:
	#	print(f"Error! Decryption for {file_path} has failed. \n\t {ERROR.__class__.__name__}\n")
"""
4.  SHA Hashing:
"""
def file_hash(file_path):
	try:
		with open(file_path, 'rb') as file:
			data = file.read()
		data_hash = hashlib.sha256(data).hexdigest()
		new_file_path = 'Hashed_Files/' + path.basename(file_path)
		with open(new_file_path, 'w') as file:
			file.write(data_hash)
		print(f"File Successfully Hashed: [{new_file_path}]. \n")
	except Exception as ERROR:
		print(f"Error! Hashing for {new_file_path} has failed. \n\t {ERROR.__class__.__name__}\n")
"""
5.  SHA Integrity Verification:
"""
def file_hash_check(file_path, file_path_hash):
	with open(file_path, 'rb') as file:
		data1 = file.read()
	data_hash1 = hashlib.sha256(data1).hexdigest()
	with open(file_path_hash, 'r') as file:
		data_hash2 = file.read()
	if data_hash1 == data_hash2:
		print('Files match! \n')
	else:
		print('Files DO NOT match! \n')
"""
6. User Interface:
"""
if 'user_profiles' in locals():
    pass
else:
	user_profiles = {}
while True:
	print("""Welcome to Cyberspace! Choose an option to continue.
	1: RSA- Generate Key Pair
	2: RSA- Encrypt
	3: RSA- Decrypt
	4: SHA256- Hash
	5: SHA256- Verify 
	6: Quit""")
	Choice = input('> ')
	if Choice == '1':
		print("Enter a new user name for the Key Pair.")
		New_User = input('> ')
		user_profiles[New_User] = User()
		print(f"User Keys Successfully Created for [{New_User}]. \n")
	elif Choice == '2':
		if len(user_profiles)>0:
			while True:
				print("Choose User Profile as recipient.")
				for i in user_profiles:
					print(f'\t{i}')
				Choice = input('> ')
				if Choice in user_profiles.keys():
					break
				else:
					print(f'[{Choice}] is not a valid input, try again.')
			Current_User = user_profiles[Choice]
			while True:
				print("Enter file path to encrypt:")
				File_Path = input('> ')
				if path.exists(File_Path):
					break
				else:
					print(f"No file found at [{File_Path}], try again.")
			file_encrypt(File_Path, Current_User)
		else:
			print("No Key pairs found.\n")
	elif Choice == '3':
		if len(user_profiles)>0:
			while True:
				print("Choose User Profile as recipient.")
				for i in user_profiles:
					print(f'\t{i}')
				Choice = input('> ')
				if Choice in user_profiles.keys():
					break
				else:
					print(f'[{Choice}] is not a valid input, try again.')
			Current_User = user_profiles[Choice]
			while True:
				print("Enter file path to decrypt:")
				File_Path = input('> ')
				if path.exists(File_Path):
					break
				else:
					print(f"No file found at [{File_Path}], try again.")
			file_decrypt(File_Path, Current_User)
			
		else:
			print("No Key pairs found.\n")
	elif Choice == '4':
		while True:
			print("Enter file path to hash:")
			File_Path = input('> ')
			if path.exists(File_Path):
				break
			else:
				print(f"No file found at [{File_Path}], try again.")
		file_hash(File_Path)
	elif Choice == '5':
		while True:
			print("Enter file path to ORIGINAL file:")
			File_Path = input('> ')
			if path.exists(File_Path):
				break
			else:
				print(f"No file found at [{File_Path}], try again.")
		while True:
			print("Enter file path to HASHED file:")
			Hash_Path = input('> ')
			if path.exists(File_Path):
				break
			else:
				print(f"No file found at [{Hash_Path}], try again.")
		file_hash_check(File_Path, Hash_Path)
	elif Choice == '6':
		break
	else:
		print(f'[{Choice}] is not a valid input, try again.')