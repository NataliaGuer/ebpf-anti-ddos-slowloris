from bcc import BPF
import socket
import struct
from datetime import datetime
import time
import subprocess
import threading

FIRST_THRESHOLD_DURATION = 5  # secondi
SECOND_THRESHOLD_DURATION = 10  # secondi
THRESHOLD_PACKETS = 5  # pacchetti
THRESHOLD_BYTES_PER_SEC = 100  # byte/s
THRESHOLD_AVG_INTERVAL = 3  # secondi tra pacchetti
SCAN_INTERVAL = 1  # secondi tra scansioni periodiche

def ip_to_str(ip_int):
    return socket.inet_ntoa(struct.pack("I", ip_int))

def get_system_uptime_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def print_conn_info(ip_str, client_port, duration_sec, packets_count, bytes_received):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] SUSPICIOUS CONNECTION DETECTED")
    print(f"  Client IP:Port    : {ip_str}:{client_port}")
    print(f"  Connection Duration: {duration_sec:.2f} seconds")
    print(f"  Packets Received  : {packets_count}")
    print(f"  Bytes Received    : {bytes_received}")
    if bytes_received > 0 and duration_sec > 0:
        print(f"  Bytes/sec         : {bytes_received / duration_sec:.2f}")
    if packets_count > 0 and duration_sec > 0:
        print(f"  Avg interval (s)  : {duration_sec / packets_count:.2f}")
    print()

def check_heuristics(duration_sec, packets_count, bytes_received):
    reasons = []
    
    # Euristica 1: 5+ secondi + < 5 pacchetti
    if duration_sec > FIRST_THRESHOLD_DURATION and packets_count < THRESHOLD_PACKETS:
        reasons.append(f"{FIRST_THRESHOLD_DURATION}s+ con solo {packets_count} pacchetti")
    
    # Euristica 2: 5+ secondi + < 100 bytes/s
    if duration_sec > FIRST_THRESHOLD_DURATION:
        bytes_per_sec = bytes_received / duration_sec if duration_sec > 0 else 0
        if bytes_per_sec < THRESHOLD_BYTES_PER_SEC:
            reasons.append(f"{FIRST_THRESHOLD_DURATION}s+ a {bytes_per_sec:.1f} bytes/s")
    
    # Euristica 3: 10+ secondi + avg interval > 3s tra pacchetti
    if duration_sec > SECOND_THRESHOLD_DURATION:
        avg_interval = duration_sec / packets_count if packets_count > 0 else duration_sec
        if avg_interval > THRESHOLD_AVG_INTERVAL:
            reasons.append(f"{SECOND_THRESHOLD_DURATION}s+ con intervallo medio {avg_interval:.1f}s tra pacchetti")
    
    return reasons

def close_connection(ip_str, client_port, server_port):
    try:
        subprocess.run([
            'ss', '-K',
            'dst', ip_str,
            'sport', '=', f':{server_port}',
            'dport', '=', f':{client_port}'
        ], capture_output=True, text=True, timeout=2)
        return True
    except Exception as e:
        print(f"[ERROR] Impossibile chiudere {ip_str}:{client_port}: {e}")
        return False

def periodic_scanner():
    while True:
        try:
            time.sleep(SCAN_INTERVAL)
            connections = b.get_table("connections")
            now_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            closed_keys = []
            
            for key, info in list(connections.items()):
                duration_ns = now_ns - info.start_time
                duration_sec = duration_ns / 1000000000.0
                
                reasons = check_heuristics(duration_sec, info.packets_count, info.bytes_received)
                
                if reasons:
                    ip_str = ip_to_str(key.client_ip)
                    print_conn_info(ip_str, key.client_port, duration_sec, 
                                   info.packets_count, info.bytes_received)
                    print(f"  Motivo: {', '.join(reasons)}")
                    print()
                    
                    if close_connection(ip_str, key.client_port, 80):
                        print(f"Connessione chiusa con successo\n")
                        closed_keys.append(key)
            
            for key in closed_keys:
                del connections[key]
                
        except Exception as e:
            print(f"[SCANNER ERROR] {e}")

def main():
    global b
    b = BPF(src_file="slowloris.bpf.c")
    b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")
    b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_return")

    scanner_thread = threading.Thread(target=periodic_scanner, daemon=True)
    scanner_thread.start()

    try:
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"Error {e}")
    except KeyboardInterrupt:
        print("\nStop")

if __name__ == "__main__":
    main()