#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

struct conn_key {
    u32 client_ip;
    u64 client_port;
};

// struttura per tracciare stato connessioni
struct conn_info {
    u64 start_time;      // inizio connessione
    u32 bytes_received;  // numero byte ricevuti
    u32 packets_count;   // numero pacchetti ricevuti
    bool notified;
};

struct event_data {
    u32 client_ip;
    u16 client_port;
    u16 server_port;
    u32 bytes_received;  // numero byte ricevuti
    u32 packets_count;   // pacchetti ricevuti
    u64 duration_ns;     // durata connessione
};

BPF_HASH(connections, struct conn_key, struct conn_info);

// utilizziamo una mappa che associa pid+tid del thread che esegue
// sia trace_tcp_recvmsg che trace_tcp_recvmsg_return alla connection key
BPF_HASH(active_reads, u64, struct conn_key);

// buffer per inviare eventi a user space
BPF_PERF_OUTPUT(events);


int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {

    if (sk == NULL) {
        return 0;
    }

    u16 server_port = 0;
    u16 client_port = 0;
    u32 client_ip = 0;

    bpf_probe_read_kernel(&server_port, sizeof(server_port), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&client_port, sizeof(client_port), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&client_ip, sizeof(client_ip), &sk->__sk_common.skc_daddr);
    
    client_port = ntohs(client_port);

    if (server_port != 80 && server_port != 443) {
        return 0;
    }

    struct conn_key key = {};
    key.client_ip = client_ip;
    key.client_port = client_port;

    // process id + thread id
    u64 pid_tid = bpf_get_current_pid_tgid();
    active_reads.update(&pid_tid, &key);

    struct conn_info *info = connections.lookup(&key);

    u64 now = bpf_ktime_get_ns();
    // se la connessione non è stata già tracciata 
    if (info == NULL) {
        struct conn_info new_conn = {};
        new_conn.start_time = now;
        new_conn.bytes_received = 0;
        new_conn.packets_count = 1;

        connections.update(&key, &new_conn);
    } else {

        if (info->notified) {
            connections.delete(&key);
            return 0;
        }

        info->packets_count++;
        u64 duration = now - info->start_time;

        bool send_event = false;

        u64 five_seconds = 5000000000;
        u64 ten_seconds = 10000000000;

        if (duration > five_seconds && info->packets_count < 5) {
            send_event = true;
        }

        if (duration > five_seconds) {
            u64 duration_sec = duration / 1000000000;
            if (duration_sec > 0) {
                u64 bytes_per_sec = info->bytes_received / duration_sec;
                if (bytes_per_sec < 100) {
                    send_event = true;
                }
            }
        }

        if (duration > ten_seconds) {
            u64 duration_sec = duration / 1000000000;
            if (info->packets_count > 0) {
                u64 avg_interval = duration_sec / info->packets_count;
                if (avg_interval > 3) {
                    send_event = true;
                }
            }
        }
        
        if (send_event) {
            struct event_data evt = {};
            evt.client_ip = client_ip;
            evt.client_port = client_port;
            evt.server_port = server_port;
            evt.bytes_received = info->bytes_received;
            evt.packets_count = info->packets_count;
            evt.duration_ns = duration;
            
            events.perf_submit(ctx, &evt, sizeof(evt));
            info->notified = true;
        }

    }

    return 0;
}

int trace_tcp_recvmsg_return(struct pt_regs *ctx) {
    int bytes_received = PT_REGS_RC(ctx);
    
    if (bytes_received <= 0) {
        return 0;
    }

    u64 pid_tid = bpf_get_current_pid_tgid();
    struct conn_key *key = active_reads.lookup(&pid_tid);

    if (key == NULL) {
        return 0;
    }

    struct conn_info *info = connections.lookup(key);

    if (info != NULL) {
        info->bytes_received += bytes_received;
    }

    active_reads.delete(&pid_tid);

    return 0;
}