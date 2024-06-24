import hashlib

def hash_combined_info(info1, info2):
    hashed_info1 = hashlib.sha512(info1.encode('utf-8')).hexdigest()
    hashed_info2 = hashlib.sha512(info2.encode('utf-8')).hexdigest()
    combined_hash = hashlib.sha512((hashed_info1 + hashed_info2).encode('utf-8')).hexdigest()
    return combined_hash


def verify_combined_info(info1, info2, combined_hash):
    hashed_info1 = hashlib.sha512(info1.encode('utf-8')).hexdigest()
    hashed_info2 = hashlib.sha512(info2.encode('utf-8')).hexdigest()
    combined_hash_calculated = hashlib.sha512((hashed_info1 + hashed_info2).encode('utf-8')).hexdigest()
    return combined_hash == combined_hash_calculated


