import logging
import os
import time
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from collections import defaultdict

# --- 1. KONFIGURASI ---
LOG_FILE = "/var/log/ids_scanner.log" # Path untuk file log
QUEUE_NUM = 0                       
SCAN_THRESHOLD = 5                  
TIME_WINDOW = 5                     
SESSION_TIMEOUT = 10                # Waktu (detik) untuk melupakan sesi SYN yang lama

# Set up logging handlers (Konsol dan File)
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Handler 1: File Handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
root_logger.addHandler(file_handler)

# Handler 2: Stream Handler (untuk output WARNING ke Terminal/Konsol)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.WARNING) 
root_logger.addHandler(console_handler)

# --- TRACKERS BARU ---
# Melacak frekuensi paket untuk Rate Limiting
SCAN_TRACKER = defaultdict(lambda: []) 

# Melacak status sesi untuk membedakan SYN vs. Full Connect
# Struktur: {IP_Sumber: {Port_Tujuan: {'state': 'SYN_SENT', 'time': timestamp}}}
SESSION_TRACKER = defaultdict(lambda: {})

# --- 2. FUNGSI KLASIFIKASI SERANGAN ---

def classify_scan(tcp_flags):
    """Mengklasifikasikan jenis scanning berdasarkan kombinasi TCP flags."""
    
    # 1. SYN Scan (Paling Umum) - Dicatat sebagai 'INIT_SYN' untuk diproses lanjut
    if tcp_flags == 'S':
        return "INIT_SYN"
    
    # 2. ACK (Hanya ACK) - Dicatat untuk diproses lanjut
    elif tcp_flags == 'A':
        return "INIT_ACK"
    
    # 3. Null Scan (Tidak ada flags)
    elif tcp_flags == '':
        return "Null Scan"
    
    # 4. Xmas Scan (FIN, PSH, URG - FPU)
    elif 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags and len(tcp_flags) == 3:
        return "Xmas Scan"

    # 5. FIN Scan (Hanya FIN)
    elif tcp_flags == 'F':
        return "FIN Scan"
        
    # 6. Full Flag Scan atau Anomali
    elif len(tcp_flags) > 4: 
        return "Full Flags Scan / Anomali"

    else:
        # Jika flags lainnya, biarkan paket lewat
        return "Lalu Lintas Standar"

# --- 3. FUNGSI DETEKSI PORT SCANNING (Rate Limiting) ---

def check_for_scan_rate(src_ip):
    # Logika rate limiting tetap sama...
    current_time = time.time()
    
    SCAN_TRACKER[src_ip] = [
        (t, c) for t, c in SCAN_TRACKER[src_ip] if current_time - t < TIME_WINDOW
    ]
    
    SCAN_TRACKER[src_ip].append((current_time, 1))
    total_packets = sum(c for t, c in SCAN_TRACKER[src_ip])
    
    if total_packets > SCAN_THRESHOLD:
        return True, total_packets
    
    return False, total_packets

# --- 4. HANDLER PAKET UTAMA ---

def packet_handler(pkt):
    payload = pkt.get_payload()
    try:
        scapy_pkt = IP(payload)
    except Exception:
        pkt.accept()
        return

    if TCP in scapy_pkt:
        ip_src = scapy_pkt[IP].src
        tcp_flags = str(scapy_pkt[TCP].flags)
        dest_port = scapy_pkt[TCP].dport 
        
        scan_type_raw = classify_scan(tcp_flags)
        
        # --- A. Pelacakan Sesi untuk SYN vs. Full Connect ---
        
        final_scan_type = scan_type_raw
        
        if scan_type_raw == "INIT_SYN":
            # Ini adalah paket awal dari SYN Scan atau Full Connect Scan.
            # Kita tandai dan berharap melihat ACK berikutnya.
            SESSION_TRACKER[ip_src][dest_port] = {'state': 'SYN_SENT', 'time': time.time()}
            final_scan_type = "SYN Scan (Half-Open)" # Asumsi awal adalah SYN Scan

        elif scan_type_raw == "INIT_ACK":
            # Periksa apakah ACK ini menyelesaikan handshake sebelumnya
            is_valid_session = False
            
            if dest_port in SESSION_TRACKER[ip_src]:
                session = SESSION_TRACKER[ip_src][dest_port]
                # Cek apakah sesi SYN_SENT masih dalam waktu timeout
                if session['state'] == 'SYN_SENT' and (time.time() - session['time'] <= SESSION_TIMEOUT):
                    
                    # Logika: Jika kita menerima ACK setelah mengirim SYN ke port ini, 
                    # itu adalah bagian dari Full Connect Scan.
                    final_scan_type = "Full TCP Connect Scan"
                    is_valid_session = True
                    # Hapus sesi setelah selesai (Full Connect)
                    del SESSION_TRACKER[ip_src][dest_port]
            
            # Jika ACK masuk tanpa SYN sebelumnya atau sesi kadaluarsa, biarkan lewat atau anggap traffic biasa
            if not is_valid_session:
                 final_scan_type = "Lalu Lintas Standar"

        
        # --- B. Proses Timeout Sesi ---
        # Bersihkan sesi lama yang sudah timeout
        current_time = time.time()
        for ip, ports in list(SESSION_TRACKER.items()):
            for port, session_data in list(ports.items()):
                if current_time - session_data['time'] > SESSION_TIMEOUT:
                    # Sesi SYN_SENT ini diabaikan (dropped) oleh penyerang, jadi itu adalah SYN Scan
                    if session_data['state'] == 'SYN_SENT':
                        log_message = (
                            f"TCP Probe Timeout: IP {ip} Port {port}. "
                            f"Confirmed as SYN Scan (Half-Open)."
                        )
                        logging.info(log_message)
                        
                    del SESSION_TRACKER[ip][port]
            if not SESSION_TRACKER[ip]:
                del SESSION_TRACKER[ip]


        # --- C. Output dan Logging ---
        
        is_scanning, packet_count = check_for_scan_rate(ip_src)
        
        if final_scan_type not in ["Lalu Lintas Standar", "INIT_ACK", "INIT_SYN"]:
            
            # Deteksi Rate Scan Tinggi (WARNING)
            if is_scanning:
                log_message = (
                    f"!!! PORT SCAN DETECTED !!! IP: {ip_src} "
                    f"Type: {final_scan_type} | Port: {dest_port} | Count: {packet_count} in {TIME_WINDOW}s"
                )
                print(log_message)
                logging.warning(log_message)
            
            # Deteksi Probe (INFO)
            else:
                log_message = (
                    f"TCP Probe Detected. IP: {ip_src} "
                    f"Type: {final_scan_type} | Port: {dest_port} | Flags: {tcp_flags}"
                )
                logging.info(log_message)

    pkt.accept()

# --- 5. FUNGSI UTAMA (MAIN LOOP) ---

def main():
    if os.geteuid() != 0:
        print("Skrip harus dijalankan dengan hak akses root (sudo) untuk menggunakan NetfilterQueue.")
        return

    print(f"[*] IDS Scanner Daemon dimulai. Mendengarkan di NFQueue {QUEUE_NUM}.")
    print(f"[*] Logging ke file: {LOG_FILE}")
    root_logger.info("IDS Scanner Daemon Started.")

    try:
        nfqueue = NetfilterQueue()
        nfqueue.bind(QUEUE_NUM, packet_handler)
        nfqueue.run() 
    except KeyboardInterrupt:
        print("\n[*] IDS Scanner Daemon dihentikan.")
        root_logger.info("IDS Scanner Daemon Stopped by user.")
    except Exception as e:
        root_logger.error(f"Kesalahan Fatal: {e}")
        print(f"[!] Kesalahan Fatal: {e}")
    finally:
        if 'nfqueue' in locals():
            nfqueue.unbind()
            
if __name__ == "__main__":
    main()