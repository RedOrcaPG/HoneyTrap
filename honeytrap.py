import logging
import os
import time
import csv
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, conf
from collections import defaultdict

# --- 1. KONFIGURASI ---
LOG_FILE = "/var/log/ids_scanner.log" 
CSV_FILE = "ids_alerts.csv"         # Nama file CSV untuk analisis skripsi
QUEUE_NUM = 0                       
SCAN_THRESHOLD = 5                  # Batas paket dalam TIME_WINDOW
TIME_WINDOW = 5                     # Jendela waktu (detik) untuk rate limiting
SESSION_TIMEOUT = 10                # Waktu (detik) untuk melupakan sesi SYN yang lama

# --- WAKTU AWAL CAPTURE (UNTUK WAKTU RELATIF) ---
# Diinisialisasi dengan 0.0, akan diubah menjadi time.time() saat paket pertama diproses.
START_CAPTURE_TIME = 0.0 

# --- CSV HEADER ---
CSV_HEADERS = [
    'Timestamp_Absolute', 'Time_Relative_Sec', 'Level', 'IP_Source', 
    'Scan_Type', 'Port_Destination', 'Flag_Seen', 'Packet_Count', 'Message'
]

# Set up logging handlers (Konsol dan File)
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
root_logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.WARNING) 
root_logger.addHandler(console_handler)

# --- TRACKERS ---
# Melacak frekuensi paket untuk Rate Limiting
SCAN_TRACKER = defaultdict(lambda: []) 

# Melacak status sesi untuk membedakan SYN vs. Full Connect
# Struktur: {IP_Sumber: {Port_Tujuan: {'state': 'SYN_SENT', 'time': timestamp}}}
SESSION_TRACKER = defaultdict(lambda: {})


# --- 2. FUNGSI KLASIFIKASI SERANGAN ---

def classify_scan(tcp_flags):
    """Mengklasifikasikan jenis scanning berdasarkan kombinasi TCP flags."""
    
    # 1. SYN Scan (Init)
    if tcp_flags == 'S':
        return "INIT_SYN"
    
    # 2. ACK (Init)
    elif tcp_flags == 'A':
        return "INIT_ACK"
    
    # 3. Null Scan
    elif tcp_flags == '':
        return "Null Scan"
    
    # 4. Xmas Scan (FIN, PSH, URG - FPU)
    elif 'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags and len(tcp_flags) == 3:
        return "Xmas Scan"
        
    # 5. FIN Scan
    elif tcp_flags == 'F':
        return "FIN Scan"
        
    # 6. Full Flag Scan atau Anomali
    elif len(tcp_flags) > 4: 
        return "Full Flags Scan / Anomali"

    else:
        return "Lalu Lintas Standar"

# --- 3. FUNGSI DETEKSI PORT SCANNING (Rate Limiting) ---

def check_for_scan_rate(src_ip):
    current_time = time.time()
    
    # Hapus paket lama di luar jendela waktu (TIME_WINDOW)
    SCAN_TRACKER[src_ip] = [
        (t, c) for t, c in SCAN_TRACKER[src_ip] if current_time - t < TIME_WINDOW
    ]
    
    SCAN_TRACKER[src_ip].append((current_time, 1))
    total_packets = sum(c for t, c in SCAN_TRACKER[src_ip])
    
    if total_packets > SCAN_THRESHOLD:
        return True, total_packets
    
    return False, total_packets

# --- 4. FUNGSI MENULIS KE CSV ---
def write_to_csv(data):
    """Menulis data log ke file CSV."""
    try:
        file_exists = os.path.isfile(CSV_FILE)
        
        with open(CSV_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            
            if not file_exists:
                writer.writerow(CSV_HEADERS)
                
            writer.writerow(data)
            
    except Exception as e:
        root_logger.error(f"Gagal menulis ke CSV: {e}")


# --- 5. HANDLER PAKET UTAMA ---

def packet_handler(pkt):
    global START_CAPTURE_TIME
    payload = pkt.get_payload()
    current_time = time.time() 
    
    # HITUNG WAKTU RELATIF (WIRESHARK STYLE)
    if START_CAPTURE_TIME == 0.0:
        # Jika ini paket alert pertama, atur titik nol
        START_CAPTURE_TIME = current_time 
        time_relative = 0.0
    else:
        # Hitung selisih waktu dari awal capture
        time_relative = current_time - START_CAPTURE_TIME
    
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
        final_scan_type = scan_type_raw
        
        # --- A. Pelacakan Sesi untuk SYN vs. Full Connect ---
        
        if scan_type_raw == "INIT_SYN":
            # Tandai sebagai sesi SYN baru
            SESSION_TRACKER[ip_src][dest_port] = {'state': 'SYN_SENT', 'time': current_time}
            final_scan_type = "SYN Scan (Half-Open)" # Asumsi awal

        elif scan_type_raw == "INIT_ACK":
            is_valid_session = False
            
            if dest_port in SESSION_TRACKER[ip_src]:
                session = SESSION_TRACKER[ip_src][dest_port]
                # Jika ACK datang setelah SYN dalam batas waktu
                if session['state'] == 'SYN_SENT' and (current_time - session['time'] <= SESSION_TIMEOUT):
                    final_scan_type = "Full TCP Connect Scan"
                    is_valid_session = True
                    # Hapus sesi karena sudah dianggap selesai
                    del SESSION_TRACKER[ip_src][dest_port]
            
            if not is_valid_session:
                 final_scan_type = "Lalu Lintas Standar"

        
        # --- B. Proses Timeout Sesi ---
        
        for ip, ports in list(SESSION_TRACKER.items()):
            for port, session_data in list(ports.items()):
                if current_time - session_data['time'] > SESSION_TIMEOUT:
                    if session_data['state'] == 'SYN_SENT':
                        log_message = (
                            f"TCP Probe Timeout: IP {ip} Port {port}. "
                            f"Confirmed as SYN Scan (Half-Open)."
                        )
                        logging.info(log_message)
                        
                        # Data CSV untuk Timeout (Waktu relatif dihitung di atas)
                        csv_data = [
                            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time)),
                            "{:.6f}".format(time_relative),
                            'INFO', ip, "SYN Scan (Timeout)", port, '', 0, log_message
                        ]
                        write_to_csv(csv_data)

                    del SESSION_TRACKER[ip][port]
            if not SESSION_TRACKER[ip]:
                del SESSION_TRACKER[ip]


        # --- C. Output dan Logging Paket Aktif ---
        
        is_scanning, packet_count = check_for_scan_rate(ip_src)
        
        if final_scan_type not in ["Lalu Lintas Standar", "INIT_ACK", "INIT_SYN"]:
            
            if is_scanning:
                log_level = "WARNING"
                log_message = (
                    f"!!! PORT SCAN DETECTED !!! IP: {ip_src} "
                    f"Type: {final_scan_type} | Port: {dest_port} | Count: {packet_count} in {TIME_WINDOW}s"
                )
                logging.warning(log_message)
            else:
                log_level = "INFO"
                log_message = (
                    f"TCP Probe Detected. IP: {ip_src} "
                    f"Type: {final_scan_type} | Port: {dest_port} | Flags: {tcp_flags}"
                )
                logging.info(log_message)
                
            # Data CSV untuk Paket Aktif (INFO/WARNING)
            csv_data = [
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time)), 
                "{:.6f}".format(time_relative),
                log_level, ip_src, final_scan_type, dest_port, 
                tcp_flags, packet_count if is_scanning else 1, log_message
            ]
            write_to_csv(csv_data)


    pkt.accept()

# --- 6. FUNGSI UTAMA (MAIN LOOP) ---

def main():
    if os.geteuid() != 0:
        print("Skrip harus dijalankan dengan hak akses root (sudo) untuk menggunakan NetfilterQueue.")
        return

    print(f"[*] IDS Scanner Daemon dimulai. Mendengarkan di NFQueue {QUEUE_NUM}.")
    print(f"[*] Logging ke file: {LOG_FILE}")
    print(f"[*] Output CSV ke file: {CSV_FILE}")
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