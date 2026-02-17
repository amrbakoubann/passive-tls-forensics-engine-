import hashlib

def calculate_ja4(protocol, version, sni_mode, ciphers, extensions):
    """
    Standard JA4 Hashing Logic
    """
    #  filter GREASE and sort
    # GREASE values (0x?A?A) are randomized by browsers and must be ignored for stable hashes
    def is_not_grease(val):
        return not (val & 0x0f0f == 0x0a0a)

    c_list = sorted([f"{c:04x}" for c in ciphers if is_not_grease(c)])
    e_list = sorted([f"{e:04x}" for e in extensions if is_not_grease(e)])

    # 2 Build Part A (Metadata)
    # Format: [protocol][version][sni][cipher_count][ext_count][alpn]
    #  '00 as a default placeholder here
    part_a = f"{protocol}{version}{sni_mode}{len(c_list):02d}{len(e_list):02d}00"

    # 3 Build Part B & C (Hashes)
    # SHA256 hashes of the sorted lists, truncated to 12 characters
    hash_b = hashlib.sha256(",".join(c_list).encode()).hexdigest()[:12]
    hash_c = hashlib.sha256(",".join(e_list).encode()).hexdigest()[:12]

    return f"{part_a}_{hash_b}_{hash_c}"