from scapy.all import sniff, IP, TLS, TLSClientHello
import sys
import os

# adding from the parent directory to path so we can import integration.db_manager
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from integration.db_manager import log_fingerprint
from ja4_logic import calculate_ja4

def packet_callback(pkt):
    if pkt.haslayer(TLSClientHello):
        tls_layer = pkt[TLSClientHello]
        ip_layer = pkt[IP]
        
        # extract
        ciphers = tls_layer.cipher_suites
        ext_list = [e.type for e in tls_layer.extensions]
        sni = "i" # default to 'i' (no SNI/IP)
        
        # Check for sni
        for ext in tls_layer.extensions:
            if hasattr(ext, 'server_names'):
                sni = "d" # Found domain-based SNI
                break
        
        # Generate the fingerprint
        ja4 = calculate_ja4('t', '13', sni, ciphers, ext_list)
        
        print(f"[!] Captured JA4: {ja4} from {ip_layer.src}")
        
        # Save to Database 
        log_fingerprint(ip_layer.src, ja4, sni)

if __name__ == "__main__":
    print("Starting Forensics Engine...")
    # Use 'sudo' to run this on Linux
    sniff(filter="tcp port 443", prn=packet_callback, store=0)