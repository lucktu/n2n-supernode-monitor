#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <arpa/inet.h>  
#include <sys/socket.h>  
#include <sys/time.h>  
#include <sys/select.h>  
#include <netdb.h>  
#include <time.h>  
#include <errno.h>  
#include <pthread.h>  
#include <fcntl.h>  
  
#define N2N_COMMUNITY_SIZE 20  
#define N2N_MAC_SIZE 6  
#define N2N_COOKIE_SIZE 4  
#define N2N_DESC_SIZE 16  
#define MSG_TYPE_REGISTER_SUPER 5  
#define COMMUNITY_LEN 16  
#define MSG_TYPE_REGISTER 1  
#define MSG_TYPE_REGISTER_ACK 4  
#define MAX_HOSTS 100  
  
static int verbose = 0;  
  
// 统计数据结构  
typedef struct {  
    char host[256];  
    int port;  
    int total_checks;  
    int success_v1;  
    int success_v2;  
    int success_v2s;  
    int success_v3;  
    time_t last_check;  
    char last_status[64];  
} host_stats_t;  
  
typedef struct {  
    host_stats_t hosts[MAX_HOSTS];  
    int host_count;  
    pthread_mutex_t lock;  
    int check_interval_minutes;  
    time_t start_time;  
    int running;  
} uptime_state_t;  
  
static uptime_state_t g_state = {0};  
  
// 编码函数  
static void encode_uint8(uint8_t *buf, size_t *idx, uint8_t val) {  
    buf[(*idx)++] = val;  
}  
  
static void encode_uint16(uint8_t *buf, size_t *idx, uint16_t val) {  
    buf[(*idx)++] = (val >> 8) & 0xff;  
    buf[(*idx)++] = val & 0xff;  
}  
  
static void encode_uint32(uint8_t *buf, size_t *idx, uint32_t val) {  
    buf[(*idx)++] = (val >> 24) & 0xff;  
    buf[(*idx)++] = (val >> 16) & 0xff;  
    buf[(*idx)++] = (val >> 8) & 0xff;  
    buf[(*idx)++] = val & 0xff;  
}  
  
static void encode_buf(uint8_t *buf, size_t *idx, const uint8_t *data, size_t len) {  
    memcpy(&buf[*idx], data, len);  
    *idx += len;  
}  
  
static void encode_common(uint8_t *buf, size_t *idx, uint8_t version, uint8_t ttl,  
                         uint16_t flags, uint8_t pc, const char *community, size_t comm_size) {  
    encode_uint8(buf, idx, version);  
    encode_uint8(buf, idx, ttl);  
    uint16_t flags_pc = (flags << 5) | (pc & 0x1f);  
    encode_uint16(buf, idx, flags_pc);  
      
    uint8_t *comm = calloc(1, comm_size);  
    strncpy((char*)comm, community, comm_size - 1);  
    encode_buf(buf, idx, comm, comm_size);  
    free(comm);  
}  
  
static void generate_random_mac(uint8_t *mac) {  
    for (int i = 0; i < N2N_MAC_SIZE; i++) {  
        mac[i] = rand() % 256;  
    }  
    mac[0] = (mac[0] | 0x02) & 0xfe;  
}  
  
// v1 数据包构造  
static size_t build_register_v1(uint8_t *pktbuf, const char *community) {  
    size_t idx = 0;  
    uint8_t mac[N2N_MAC_SIZE];  
      
    generate_random_mac(mac);  
      
    encode_uint8(pktbuf, &idx, 1);  
    encode_uint8(pktbuf, &idx, MSG_TYPE_REGISTER);  
    encode_uint8(pktbuf, &idx, 2);  
    encode_uint8(pktbuf, &idx, 0);  
      
    uint8_t comm[COMMUNITY_LEN] = {0};  
    strncpy((char*)comm, community, COMMUNITY_LEN - 1);  
    encode_buf(pktbuf, &idx, comm, COMMUNITY_LEN);  
      
    encode_buf(pktbuf, &idx, mac, N2N_MAC_SIZE);  
      
    uint8_t dst_mac[N2N_MAC_SIZE] = {0};  
    encode_buf(pktbuf, &idx, dst_mac, N2N_MAC_SIZE);  
      
    uint8_t public_peer[20] = {0};  
    encode_buf(pktbuf, &idx, public_peer, 20);  
      
    uint8_t private_peer[20] = {0};  
    encode_buf(pktbuf, &idx, private_peer, 20);  
      
    encode_uint8(pktbuf, &idx, 0);  
    encode_uint8(pktbuf, &idx, 0);  
    encode_uint8(pktbuf, &idx, 0);  
    encode_uint8(pktbuf, &idx, 0);  
      
    encode_uint32(pktbuf, &idx, 0);  
    encode_uint32(pktbuf, &idx, 0);  
      
    return idx;  
}  
  
// v2 数据包构造 (无 aflags/timeout)  
static size_t build_register_super_v2(uint8_t *pktbuf, const char *community, uint8_t *sent_cookie) {  
    size_t idx = 0;  
    uint8_t mac[N2N_MAC_SIZE];  
      
    sent_cookie[0] = 0xAA;  
    sent_cookie[1] = 0xBB;  
    sent_cookie[2] = 0xCC;  
    sent_cookie[3] = 0xDD;  
      
    generate_random_mac(mac);  
    encode_common(pktbuf, &idx, 2, 2, 0, MSG_TYPE_REGISTER_SUPER, community, N2N_COMMUNITY_SIZE);  
    // v2: cookie 直接跟在 common header 后  
    encode_buf(pktbuf, &idx, sent_cookie, N2N_COOKIE_SIZE);  
    encode_buf(pktbuf, &idx, mac, N2N_MAC_SIZE);  
    encode_uint32(pktbuf, &idx, 0);  
    encode_uint8(pktbuf, &idx, 0);  
    encode_uint16(pktbuf, &idx, 0);  
    encode_uint16(pktbuf, &idx, 0);  
      
    return idx;  
}  
  
// v2s 数据包构造 (有 aflags/timeout)  
static size_t build_register_super_v2s(uint8_t *pktbuf, const char *community, uint8_t *sent_cookie) {  
    size_t idx = 0;  
    uint8_t mac[N2N_MAC_SIZE];  
      
    sent_cookie[0] = 0x11;  
    sent_cookie[1] = 0x22;  
    sent_cookie[2] = 0x33;  
    sent_cookie[3] = 0x44;  
      
    generate_random_mac(mac);  
    encode_common(pktbuf, &idx, 2, 2, 0, MSG_TYPE_REGISTER_SUPER, community, N2N_COMMUNITY_SIZE);  
    // v2s: aflags 和 timeout 在 cookie 之前  
    encode_uint16(pktbuf, &idx, 0x0001);  // aflags  
    encode_uint16(pktbuf, &idx, 60);      // timeout  
    encode_buf(pktbuf, &idx, sent_cookie, N2N_COOKIE_SIZE);  
    encode_buf(pktbuf, &idx, mac, N2N_MAC_SIZE);  
    encode_uint16(pktbuf, &idx, 0);  
    encode_uint16(pktbuf, &idx, 0);  
      
    return idx;  
}  
  
// v3 数据包构造  
static size_t build_register_super_v3(uint8_t *pktbuf, const char *community, uint8_t *sent_cookie) {  
    size_t idx = 0;  
    uint8_t mac[N2N_MAC_SIZE];  
    uint8_t dev_desc[N2N_DESC_SIZE] = {0};  
      
    // 使用固定 cookie 标识 v3  
    sent_cookie[0] = 0x55;  
    sent_cookie[1] = 0x66;  
    sent_cookie[2] = 0x77;  
    sent_cookie[3] = 0x88;  
      
    generate_random_mac(mac);  
      
    encode_common(pktbuf, &idx, 3, 3, 0, MSG_TYPE_REGISTER_SUPER, community, N2N_COMMUNITY_SIZE);  
    encode_buf(pktbuf, &idx, sent_cookie, N2N_COOKIE_SIZE);  // 使用固定 cookie  
    encode_buf(pktbuf, &idx, mac, N2N_MAC_SIZE);  
    encode_uint32(pktbuf, &idx, 0);  
    encode_uint8(pktbuf, &idx, 0);  
    encode_buf(pktbuf, &idx, dev_desc, N2N_DESC_SIZE);  
    encode_uint16(pktbuf, &idx, 0);  
    encode_uint16(pktbuf, &idx, 0);  
    encode_uint32(pktbuf, &idx, 0);  
      
    return idx;  
}  
  
// 响应验证函数  
static int is_valid_v1_ack(const uint8_t *buf, size_t len) {  
    if (len < 2) return 0;  
    uint8_t msg_type = buf[1];  
    return (msg_type == MSG_TYPE_REGISTER_ACK);  
}  
  
static int is_valid_v2_ack(const uint8_t *buf, size_t len, const uint8_t *expected_cookie) {  
    if (len < 28) return 0;  
      
    uint16_t flags_pc = (buf[2] << 8) | buf[3];  
    uint8_t pc = flags_pc & 0x1f;  
    if (pc != 6) return 0;  
      
    const uint8_t *received_cookie = buf + 24;  
    return memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;  
}  
  
static int is_valid_v2s_ack(const uint8_t *buf, size_t len, const uint8_t *expected_cookie) {  
    if (len < 28) return 0;  
      
    uint16_t flags_pc = (buf[2] << 8) | buf[3];  
    uint8_t pc = flags_pc & 0x1f;  
    if (pc != 6) return 0;  
      
    const uint8_t *received_cookie = buf + 24;  
    return memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;  
}  
  
static int is_valid_v3_ack(const uint8_t *buf, size_t len, const uint8_t *expected_cookie) {  
    if (len < 28) return 0;  // 确保包长度足够读取 cookie  
      
    uint16_t flags_pc = (buf[2] << 8) | buf[3];  
    uint8_t pc = flags_pc & 0x1f;  
    if (pc != 6 && pc != 7) return 0;  // 检查 packet code  
      
    // 验证 cookie 位置(common header 后 24 字节处)  
    const uint8_t *received_cookie = buf + 24;  
    return memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;  
}  
  
// 检测单个 supernode  
int test_supernode_internal(const char *host, int port, int *v1_ok, int *v2_ok, int *v2s_ok, int *v3_ok) {  
    struct sockaddr_in addr;  
    uint8_t pktbuf_v1[2048], pktbuf_v2[2048], pktbuf_v2s[2048], pktbuf_v3[2048];  
    uint8_t recvbuf[2048];  
      
    uint8_t cookie_v2[N2N_COOKIE_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};  
    uint8_t cookie_v2s[N2N_COOKIE_SIZE] = {0x11, 0x22, 0x33, 0x44};
    uint8_t cookie_v3[N2N_COOKIE_SIZE] = {0x55, 0x66, 0x77, 0x88};  
      
    struct addrinfo hints = {0};  
    struct addrinfo *result = NULL;  
      
    *v1_ok = *v2_ok = *v2s_ok = *v3_ok = 0;  
      
    hints.ai_family = AF_INET;  
    hints.ai_socktype = SOCK_DGRAM;  
      
    if (getaddrinfo(host, NULL, &hints, &result) != 0) {  
        return -1;  
    }  
      
    memset(&addr, 0, sizeof(addr));  
    addr.sin_family = AF_INET;  
    addr.sin_port = htons(port);  
    addr.sin_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr;  
    freeaddrinfo(result);  
      
    // 生成随机社区名  
    char community[N2N_COMMUNITY_SIZE];  
    snprintf(community, sizeof(community), "test%d", rand() % 10000);  
      
    // 构造四个版本的数据包  
    size_t pkt_len_v1 = build_register_v1(pktbuf_v1, community);  
    size_t pkt_len_v2 = build_register_super_v2(pktbuf_v2, community, cookie_v2);  
    size_t pkt_len_v2s = build_register_super_v2s(pktbuf_v2s, community, cookie_v2s);  
    size_t pkt_len_v3 = build_register_super_v3(pktbuf_v3, community, cookie_v3);    
      
    // 只创建一个 socket  
    int sock = socket(AF_INET, SOCK_DGRAM, 0);  
    if (sock < 0) {  
        fprintf(stderr, "✗ %s:%d - Socket 创建失败: %s\n", host, port, strerror(errno));  
        return -1;  
    }  
      
    // 设置非阻塞模式  
    int flags = fcntl(sock, F_GETFL, 0);  
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);  
      
    // 发送所有数据包  
    sendto(sock, pktbuf_v1, pkt_len_v1, 0, (struct sockaddr*)&addr, sizeof(addr));  
    sendto(sock, pktbuf_v2, pkt_len_v2, 0, (struct sockaddr*)&addr, sizeof(addr));  
    sendto(sock, pktbuf_v2s, pkt_len_v2s, 0, (struct sockaddr*)&addr, sizeof(addr));  
    sendto(sock, pktbuf_v3, pkt_len_v3, 0, (struct sockaddr*)&addr, sizeof(addr));  
      
    // 使用 gettimeofday 获得微秒级精度  
    struct timeval start_tv, now_tv;  
    gettimeofday(&start_tv, NULL);  
    long timeout_ms = 800;  // 800ms 总超时  
    int responses_received = 0;  
    int consecutive_empty = 0;  
      
    while (1) {  
        gettimeofday(&now_tv, NULL);  
        long elapsed_ms = (now_tv.tv_sec - start_tv.tv_sec) * 1000 +   
                          (now_tv.tv_usec - start_tv.tv_usec) / 1000;  
          
        if (elapsed_ms >= timeout_ms) break;  
          
        // 如果已收到所有可能的响应,提前退出  
        if (*v1_ok && *v2_ok && *v2s_ok && *v3_ok) {  
            if (verbose) {  
                fprintf(stderr, "[DEBUG] %s:%d 所有版本响应已收到,提前退出\n", host, port);  
            }  
            break;  
        }  
          
        // 尝试接收数据  
        ssize_t recv_len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);  
          
        if (recv_len < 0) {  
            if (errno == EAGAIN || errno == EWOULDBLOCK) {  
                // 没有数据可读  
                consecutive_empty++;  
                if (consecutive_empty >= 5 && responses_received > 0) {  
                    // 连续 5 次没数据且已收到至少一个响应,可能不会再有响应了  
                    break;  
                }  
                usleep(20000);  // 等待 20ms  
                continue;  
            } else {  
                // 其他错误  
                break;  
            }  
        }  
          
        consecutive_empty = 0;  
        responses_received++;  
          
        // 根据响应内容判断版本  
        if (recv_len >= 2 && !*v1_ok) {  
            if (is_valid_v1_ack(recvbuf, recv_len)) {  
                *v1_ok = 1;  
                if (verbose) {  
                    fprintf(stderr, "[DEBUG] %s:%d 检测到 v1 响应\n", host, port);  
                }  
                continue;  
            }  
        }  
          
        if (recv_len >= 28 && !*v2_ok) {  
            if (is_valid_v2_ack(recvbuf, recv_len, cookie_v2)) {  
                *v2_ok = 1;  
                if (verbose) {  
                    fprintf(stderr, "[DEBUG] %s:%d 检测到 v2 响应\n", host, port);  
                }  
                continue;  
            }  
        }  
          
        if (recv_len >= 28 && !*v2s_ok) {  
            if (is_valid_v2s_ack(recvbuf, recv_len, cookie_v2s)) {  
                *v2s_ok = 1;  
                if (verbose) {  
                    fprintf(stderr, "[DEBUG] %s:%d 检测到 v2s 响应\n", host, port);  
                }  
                continue;  
            }  
        }  
          
        if (recv_len >= 28 && !*v3_ok) {  
            if (is_valid_v3_ack(recvbuf, recv_len, cookie_v3)) {  
                *v3_ok = 1;  
                if (verbose) {  
                    fprintf(stderr, "[DEBUG] %s:%d 检测到 v3 响应\n", host, port);  
                }  
                continue;  
            }  
        }  
    }  
      
    close(sock);  
      
    // 记录所有检测到的版本  
    const char *detected_versions[4] = {NULL, NULL, NULL, NULL};  
    int version_count = 0;  
      
    if (*v1_ok) detected_versions[version_count++] = "v1";  
    if (*v2_ok) detected_versions[version_count++] = "v2";  
    if (*v2s_ok) detected_versions[version_count++] = "v2s";  
    if (*v3_ok) detected_versions[version_count++] = "v3";  
      
    // 输出检测结果  
    if (version_count > 0) {  
        printf("\t✓ %s:%d - 检测成功 (版本: ", host, port);  
        for (int i = 0; i < version_count; i++) {  
            printf("%s", detected_versions[i]);  
            if (i < version_count - 1) printf(", ");  
        }  
        printf(")\n\n");  
        return 0;  
    } else { 
    	if (verbose) {  
                fprintf(stderr, "[DEBUG] %s:%d 未收到任何响应，主机不可达？端口关闭？被过滤？\n", host, port);  
        } 
        printf("\t✗ %s:%d - 无法连接\n\n", host, port);  
        return -1;  
    }  
}
  
int main(int argc, char *argv[]) { 
    setbuf(stdout, NULL);  // 禁用 stdout 缓冲 
    srand(time(NULL));  
      
    int arg_start = 1;  
      
    // 解析命令行选项  
    if (argc >= 2 && strcmp(argv[1], "-v") == 0) {  
        verbose = 1;  
        arg_start = 2;  
    }  
      
    if (argc < arg_start + 1) {  
        printf("用法: %s [-v] <主机1:端口1> [主机2:端口2] ...\n", argv[0]);  
        printf("示例: %s n2n.example.com:10086 192.168.1.1:10090\n", argv[0]);  
        printf("选项:\n");  
        printf("  -v    详细模式（显示调试信息）\n");  
        return 1;  
    }  
     
    for (int i = arg_start; i < argc; i++) {  
        char *host = strdup(argv[i]);  
        if (!host) {  
            fprintf(stderr, "错误: 内存分配失败\n");  
            continue;  
        }  
          
        char *port_str = strchr(host, ':');  
        int port = 10086;  
          
        if (port_str) {  
            *port_str = '\0';  
            port = atoi(port_str + 1); 
            if (port <= 0 || port > 65535) {
            	fprintf(stderr, "错误: 无效的端口号 %d\n", port);
            	free(host);
            	continue;
            } 
        }  
          
        int v1_ok = 0, v2_ok = 0, v2s_ok = 0, v3_ok = 0;
        test_supernode_internal(host, port, &v1_ok, &v2_ok, &v2s_ok, &v3_ok); 
        free(host);  
          
        if (i < argc - 1) {  
            usleep(100000);  
        }  
    }  
      
    return 0;  
}
