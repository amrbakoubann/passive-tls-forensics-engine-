import hashlib

def generate_ja4(protocol, version, ciphers, extensions):
    """
    Standard JA4 Hashing Logic
    protocol: 't' for TCP
    version: TLS version (e.g., '13' for 1.3)
    ciphers: list of cipher suite decimal values
    extensions: list of extension decimal values
    """
    
    #  Sort values numerically (for JA4 standard)
    ciphers.sort()
    extensions.sort()
    
    #  Convert lists to comma-separated strings
    cipher_str = ",".join(map(str, ciphers))
    ext_str = ",".join(map(str, extensions))
    
    # Create SHA256 hashes of the sorted strings (truncated to 12 chars)
    cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]
    ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]
    
    #  Final JA4 String: [Protocol][Version]_[CipherHash]_[ExtensionHash]
    ja4_fingerprint = f"{protocol}{version}_{cipher_hash}_{ext_hash}"
    
    return ja4_fingerprint

# example  from a captured packet:
# print(generate_ja4('t', '13', [4865, 4866, 4867], [0, 23, 65281]))