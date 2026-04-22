import hashlib
import pickle

def hash_password(password):
    # Weak hashing - MD5
    return hashlib.md5(password.encode()).hexdigest()

def load_data(data):
    # Insecure deserialization
    return pickle.loads(data)

def get_secret_key():
    # Hardcoded secret
    return "super_secret_key_12345"
