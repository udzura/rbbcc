from bcc import BPF, lib
import socket
import ctypes
import os

# 1. C言語側のプログラム
program = r"""
#include <linux/lsm_hooks.h>
#include <linux/socket.h>
#include <uapi/asm-generic/errno-base.h>

struct data_t {
    u32 pid;
    int family;
    int type;
    int is_warning;
    int is_blocked;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// モード保存用マップ (Index 0 を使用)
// 1: blockモード, 0: previewモード
BPF_ARRAY(config_map, u32, 1);

LSM_PROBE(socket_create, int family, int type, int protocol, int kern)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t data = {};
    
    // マップから現在のモードを取得
    u32 key = 0;
    u32 *mode = config_map.lookup(&key);
    int is_block_mode = (mode && *mode == 1);

    data.pid = pid;
    data.family = family;
    data.type = type;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (family == AF_ALG) {
        data.is_blocked = is_block_mode;
        data.is_warning = 1;

        // ログデータを送信
        events.perf_submit(ctx, &data, sizeof(data));

        // blockモードならエラーを返してシステムコールを失敗させる
        if (is_block_mode) {
            return -EPERM; // -1 (Operation not permitted)
        }
    } else {
        data.is_blocked = 0;
        data.is_warning = 0;

        // ログデータを送信
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

# 定数解決用
families = {getattr(socket, n): n for n in dir(socket) if n.startswith('AF_')}
types = {getattr(socket, n): n for n in dir(socket) if n.startswith('SOCK_')}

def print_event(cpu, data, size):
    event = b["events"].event(data)

    family_str = families.get(event.family, f"AF_UNKNOWN({event.family})")
    type_str = types.get(event.type, f"SOCK_UNKNOWN({event.type})")
    
    print(f"PID: {event.pid:<7} | COMM: {event.comm.decode('utf-8'):<15} | "
          f"FAMILY: {family_str:<12} | TYPE: {type_str}")

    if event.is_warning:
        mode_str = "BLOCK" if event.is_blocked else "PREVIEW"
        status = "!! REJECTED !!" if event.is_blocked else "WARNING"
        
        print(f"[{mode_str}] {status}: PID {event.pid} ({event.comm.decode()}) "
            f"tried to create AF_ALG socket.")

# 2. ロードと設定
try:
    b = BPF(text=program)
    
    # --- モード設定 ---
    # 1 を書き込むと blockモード、0 だと previewモード
    mode = 0
    config_table = b.get_table("config_map")
    config_table[ctypes.c_uint32(0)] = ctypes.c_uint32(mode)

    # Mapの永続化 - ユーザ空間からモードを変更できるようにするため
    map_path = "/sys/fs/bpf/my_config_map"
    if os.path.exists(map_path):
        os.remove(map_path)
    print(f"Pinning config map to -> {map_path}")
    map_fd = config_table.get_fd()
    res = lib.bpf_obj_pin(map_fd, ctypes.c_char_p(map_path.encode()))
    if res != 0:
        raise Exception(f"Failed to pin map to {map_path}: {os.strerror(-res)}")

    # -----------------

    print(f"LSM BPF started in {'BLOCK' if mode == 1 else 'PREVIEW'} mode.")
    print("Tracing AF_ALG creation... Press Ctrl-C to exit.")
    
    b["events"].open_perf_buffer(print_event)
    
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

except Exception as e:
    print(f"Failed: {e}")