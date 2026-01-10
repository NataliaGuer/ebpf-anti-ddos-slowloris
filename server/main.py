from bcc import BPF
import socket
import struct
from datetime import datetime
import time
import subprocess

def ip_to_str(ip_int):
    """Converti u32 in stringa IP"""
    return socket.inet_ntoa(struct.pack("I", ip_int))

def get_system_uptime_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def print_event(data):
    event = b["events"].event(data)
    ip_str = ip_to_str(event.client_ip)
    duration_sec = event.duration_ns / 1000000000.0
    timestamp = datetime.now().strftime("%H:%M:%S")

    print(f"[{timestamp}] SUSPICIOUS CONNECTION")
    print(f"  Client IP:Port    : {ip_str}:{event.client_port}")
    print(f"  Server Port       : {event.server_port}")
    print(f"  Connection Duration: {duration_sec:.2f} seconds")
    print(f"  Packets Received  : {event.packets_count}")
    print(f"  Bytes Received    : {event.bytes_received}")
    print()

def handle_event(cpu, data, size):
    print("\n")
    print_event(data)
    event = b["events"].event(data)
    ip_str = ip_to_str(event.client_ip)
    conn_id = f"{ip_str}:{event.client_port}"

    connections = b.get_table("connections")

    try:
        # Usa ss per chiudere la socket con TCP RST
        # Formato: ss -K dst IP sport = :SERVER_PORT dport = :CLIENT_PORT
        result = subprocess.run([
            'ss', '-K',
            'dst', ip_str,
            'sport', '=', f':{event.server_port}',
            'dport', '=', f':{event.client_port}'
        ], capture_output=True, text=True, timeout=2)
        
        print(f"[SOCKET CLOSED] {ip_str}:{event.client_port} -> :{event.server_port}")
        return True
    except Exception as e:
        print(f"[ERROR] Impossibile chiudere socket {conn_id}: {e}")
        return False

def main():
    global b
    b = BPF(src_file="slowloris.bpf.c")
    b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg")
    b.attach_kretprobe(event="tcp_recvmsg", fn_name="trace_tcp_recvmsg_return")

    b["events"].open_perf_buffer(handle_event)

    try:
        while True:
            b.perf_buffer_poll()
    except Exception as e:
        print(f"Error {e}")
    except KeyboardInterrupt:
        print("Stopping")

if __name__ == "__main__":
    main()