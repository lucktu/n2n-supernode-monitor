#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>

#define N2N_COMMUNITY_SIZE 20
#define N2N_MAC_SIZE 6
#define N2N_COOKIE_SIZE 4
#define N2N_DESC_SIZE 16
#define MSG_TYPE_REGISTER_SUPER 5
#define COMMUNITY_LEN 16
#define MSG_TYPE_REGISTER 1
#define MSG_TYPE_REGISTER_ACK 4
#define MAX_HOSTS 100
#define MAX_HISTORY 300 // 保存300次检测记录
#define STATE_DIR "/tmp/n2n_monitor"

static int verbose = 0;
static char g_community[N2N_COMMUNITY_SIZE] = "N2N_check_bot";
static uint8_t g_mac[N2N_MAC_SIZE] = {0xa1, 0xb2, 0xc3, 0xd4, 0xf5, 0x06}; // a1:b2:c3:d4:f5:06

// 单次检测记录
typedef struct
{
    time_t timestamp;
    int success; // 0=离线, 1=在线
} check_record_t;

// 统计数据结构
typedef struct
{
    char host[256];
    int port;
    char note[2048]; // 备注
    int total_checks;
    int success_v1;
    int success_v2;
    int success_v2s;
    int success_v3;
    time_t last_check;
    char last_status[64];
    check_record_t history[MAX_HISTORY]; // 循环历史记录
    int history_index;                   // 当前写入位置
    int history_count;                   // 已有记录数
} host_stats_t;

typedef struct
{
    host_stats_t hosts[MAX_HOSTS];
    int host_count;
    pthread_mutex_t lock;
    int check_interval_minutes;
    time_t start_time;
    int running;
	char config_file_path[1024];  // :配置文件路径  
    time_t config_mtime;         // 配置文件最后修改时间 
} uptime_state_t;

static uptime_state_t g_state = {0};

// 编码函数
static void encode_uint8(uint8_t *buf, size_t *idx, uint8_t val)
{
    buf[(*idx)++] = val;
}

static void encode_uint16(uint8_t *buf, size_t *idx, uint16_t val)
{
    buf[(*idx)++] = (val >> 8) & 0xff;
    buf[(*idx)++] = val & 0xff;
}

static void encode_uint32(uint8_t *buf, size_t *idx, uint32_t val)
{
    buf[(*idx)++] = (val >> 24) & 0xff;
    buf[(*idx)++] = (val >> 16) & 0xff;
    buf[(*idx)++] = (val >> 8) & 0xff;
    buf[(*idx)++] = val & 0xff;
}

static void encode_buf(uint8_t *buf, size_t *idx, const uint8_t *data, size_t len)
{
    memcpy(&buf[*idx], data, len);
    *idx += len;
}

static void encode_common(uint8_t *buf, size_t *idx, uint8_t version, uint8_t ttl,
                          uint16_t flags, uint8_t pc, const char *community, size_t comm_size)
{
    encode_uint8(buf, idx, version);
    encode_uint8(buf, idx, ttl);
    uint16_t flags_pc = (flags << 5) | (pc & 0x1f);
    encode_uint16(buf, idx, flags_pc);

    uint8_t *comm = calloc(1, comm_size);
    strncpy((char *)comm, community, comm_size - 1);
    encode_buf(buf, idx, comm, comm_size);
    free(comm);
}

// 解析MAC地址字符串 (格式: a1:b2:c3:d4:f5:g6)
static int parse_mac(const char *mac_str, uint8_t *mac)
{
    int values[N2N_MAC_SIZE];
    int count = sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                       &values[0], &values[1], &values[2],
                       &values[3], &values[4], &values[5]);

    if (count != N2N_MAC_SIZE)
    {
        return -1;
    }

    for (int i = 0; i < N2N_MAC_SIZE; i++)
    {
        if (values[i] < 0 || values[i] > 0xFF)
        {
            return -1;
        }
        mac[i] = (uint8_t)values[i];
    }

    return 0;
}

// 创建一个辅助函数用于生成时间戳
static const char *timestamp(void)
{
    static char buf[128];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

// v1 数据包构造
static size_t build_register_v1(uint8_t *pktbuf, const char *community)
{
    size_t idx = 0;
    uint8_t mac[N2N_MAC_SIZE];

    memcpy(mac, g_mac, N2N_MAC_SIZE);

    encode_uint8(pktbuf, &idx, 1);
    encode_uint8(pktbuf, &idx, MSG_TYPE_REGISTER);
    encode_uint8(pktbuf, &idx, 2);
    encode_uint8(pktbuf, &idx, 0);

    uint8_t comm[COMMUNITY_LEN] = {0};
    strncpy((char *)comm, community, COMMUNITY_LEN - 1);
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
static size_t build_register_super_v2(uint8_t *pktbuf, const char *community, uint8_t *sent_cookie)
{
    size_t idx = 0;
    uint8_t mac[N2N_MAC_SIZE];

    sent_cookie[0] = 0xAA;
    sent_cookie[1] = 0xBB;
    sent_cookie[2] = 0xCC;
    sent_cookie[3] = 0xDD;

    memcpy(mac, g_mac, N2N_MAC_SIZE);
    encode_common(pktbuf, &idx, 2, 2, 0, MSG_TYPE_REGISTER_SUPER, community, N2N_COMMUNITY_SIZE);
    encode_buf(pktbuf, &idx, sent_cookie, N2N_COOKIE_SIZE);
    encode_buf(pktbuf, &idx, mac, N2N_MAC_SIZE);
    encode_uint32(pktbuf, &idx, 0);
    encode_uint8(pktbuf, &idx, 0);
    encode_uint16(pktbuf, &idx, 0);
    encode_uint16(pktbuf, &idx, 0);

    return idx;
}

// v2s 数据包构造 (有 aflags/timeout)
static size_t build_register_super_v2s(uint8_t *pktbuf, const char *community, uint8_t *sent_cookie)
{
    size_t idx = 0;
    uint8_t mac[N2N_MAC_SIZE];

    sent_cookie[0] = 0x11;
    sent_cookie[1] = 0x22;
    sent_cookie[2] = 0x33;
    sent_cookie[3] = 0x44;

    memcpy(mac, g_mac, N2N_MAC_SIZE);
    encode_common(pktbuf, &idx, 2, 2, 0, MSG_TYPE_REGISTER_SUPER, community, N2N_COMMUNITY_SIZE);
    encode_uint16(pktbuf, &idx, 0x0001); // aflags
    encode_uint16(pktbuf, &idx, 60);     // timeout
    encode_buf(pktbuf, &idx, sent_cookie, N2N_COOKIE_SIZE);
    encode_buf(pktbuf, &idx, mac, N2N_MAC_SIZE);
    encode_uint16(pktbuf, &idx, 0);
    encode_uint16(pktbuf, &idx, 0);

    return idx;
}

// v3 数据包构造
static size_t build_register_super_v3(uint8_t *pktbuf, const char *community, uint8_t *sent_cookie)
{
    size_t idx = 0;
    uint8_t mac[N2N_MAC_SIZE];
    uint8_t dev_desc[N2N_DESC_SIZE] = {0};

    sent_cookie[0] = 0x55;
    sent_cookie[1] = 0x66;
    sent_cookie[2] = 0x77;
    sent_cookie[3] = 0x88;

    memcpy(mac, g_mac, N2N_MAC_SIZE);

    encode_common(pktbuf, &idx, 3, 3, 0, MSG_TYPE_REGISTER_SUPER, community, N2N_COMMUNITY_SIZE);
    encode_buf(pktbuf, &idx, sent_cookie, N2N_COOKIE_SIZE);
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
static int is_valid_v1_ack(const uint8_t *buf, size_t len)
{
    if (len < 2)
        return 0;
    uint8_t msg_type = buf[1];
    int is_valid = (msg_type == MSG_TYPE_REGISTER_ACK);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]:    msg_type: %d (期望: %d)\n",
                timestamp(), msg_type, MSG_TYPE_REGISTER_ACK);
        fprintf(stderr, "[%s] [DEBUG]:    结果: %s\n",
                timestamp(), is_valid ? "✓ 有效" : "✗ 无效");
    }

    return is_valid;
}

static int is_valid_v2_ack(const uint8_t *buf, size_t len, const uint8_t *expected_cookie)
{
    if (len < 28)
        return 0;

    uint16_t flags_pc = (buf[2] << 8) | buf[3];
    uint8_t pc = flags_pc & 0x1f;
    if (pc != 6)
        return 0;

    const uint8_t *received_cookie = buf + 24;
    int cookie_match = memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]:    期望 cookie: %02x:%02x:%02x:%02x\n",
                timestamp(), expected_cookie[0], expected_cookie[1],
                expected_cookie[2], expected_cookie[3]);
        fprintf(stderr, "[%s] [DEBUG]:    收到 cookie: %02x:%02x:%02x:%02x\n",
                timestamp(), received_cookie[0], received_cookie[1],
                received_cookie[2], received_cookie[3]);
        fprintf(stderr, "[%s] [DEBUG]:    结果: %s\n",
                timestamp(), cookie_match ? "✓ 有效" : "✗ cookie 不匹配");
    }
    return memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;
}

static int is_valid_v2s_ack(const uint8_t *buf, size_t len, const uint8_t *expected_cookie)
{
    if (len < 28)
        return 0;

    uint16_t flags_pc = (buf[2] << 8) | buf[3];
    uint8_t pc = flags_pc & 0x1f;
    if (pc != 6)
        return 0;

    const uint8_t *received_cookie = buf + 24;
    int cookie_match = memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]:    期望 cookie: %02x:%02x:%02x:%02x\n",
                timestamp(), expected_cookie[0], expected_cookie[1],
                expected_cookie[2], expected_cookie[3]);
        fprintf(stderr, "[%s] [DEBUG]:    收到 cookie: %02x:%02x:%02x:%02x\n",
                timestamp(), received_cookie[0], received_cookie[1],
                received_cookie[2], received_cookie[3]);
        fprintf(stderr, "[%s] [DEBUG]:    结果: %s\n",
                timestamp(), cookie_match ? "✓ 有效" : "✗ cookie 不匹配");
    }
    return memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;
}

static int is_valid_v3_ack(const uint8_t *buf, size_t len, const uint8_t *expected_cookie)
{
    if (len < 28)
        return 0;

    uint16_t flags_pc = (buf[2] << 8) | buf[3];
    uint8_t pc = flags_pc & 0x1f;
    if (pc != 6 && pc != 7)
        return 0;

    const uint8_t *received_cookie = buf + 24;
    int cookie_match = memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]:    期望 cookie: %02x:%02x:%02x:%02x\n",
                timestamp(), expected_cookie[0], expected_cookie[1],
                expected_cookie[2], expected_cookie[3]);
        fprintf(stderr, "[%s] [DEBUG]:    收到 cookie: %02x:%02x:%02x:%02x\n",
                timestamp(), received_cookie[0], received_cookie[1],
                received_cookie[2], received_cookie[3]);
        fprintf(stderr, "[%s] [DEBUG]:    结果: %s\n",
                timestamp(), cookie_match ? "✓ 有效" : "✗ cookie 不匹配");
    }
    return memcmp(received_cookie, expected_cookie, N2N_COOKIE_SIZE) == 0;
}

// 检测单个 supernode (使用单socket非阻塞方式)
int test_supernode_internal(const char *host, int port, int *v1_ok, int *v2_ok, int *v2s_ok, int *v3_ok)
{
    struct sockaddr_in addr;
    uint8_t pktbuf_v1[2048], pktbuf_v2[2048], pktbuf_v2s[2048], pktbuf_v3[2048];
    uint8_t recvbuf[2048];

    uint8_t cookie_v2[N2N_COOKIE_SIZE] = {0xA2, 0xB2, 0xC2, 0xD2};
    uint8_t cookie_v2s[N2N_COOKIE_SIZE] = {0x11, 0x22, 0x33, 0x44};
    uint8_t cookie_v3[N2N_COOKIE_SIZE] = {0xA3, 0xB3, 0xC3, 0xD3};

    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;

    *v1_ok = *v2_ok = *v2s_ok = *v3_ok = 0;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, NULL, &hints, &result) != 0)
    {
        fprintf(stderr, "[%s] [ERROR]: %s:%d DNS 解析失败: %s\n", timestamp(), host, port, strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
    freeaddrinfo(result);

    if (verbose)
    {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 解析为 %s:%d\n", timestamp(), host, port, ip_str, port);
    }

    char community[N2N_COMMUNITY_SIZE];
    strncpy(community, g_community, N2N_COMMUNITY_SIZE - 1);
    community[N2N_COMMUNITY_SIZE - 1] = '\0';

    size_t pkt_len_v1 = build_register_v1(pktbuf_v1, community);
    size_t pkt_len_v2 = build_register_super_v2(pktbuf_v2, community, cookie_v2);
    size_t pkt_len_v2s = build_register_super_v2s(pktbuf_v2s, community, cookie_v2s);
    size_t pkt_len_v3 = build_register_super_v3(pktbuf_v3, community, cookie_v3);

    // 只创建一个 socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        fprintf(stderr, "[%s] [ERROR]: %s:%d - Socket 创建失败: %s\n", timestamp(), host, port, strerror(errno));
        return -1;
    }

    // 设置非阻塞模式
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // 发送所有数据包并记录状态
    ssize_t sent_v1 = sendto(sock, pktbuf_v1, pkt_len_v1, 0, (struct sockaddr *)&addr, sizeof(addr));
    ssize_t sent_v2 = sendto(sock, pktbuf_v2, pkt_len_v2, 0, (struct sockaddr *)&addr, sizeof(addr));
    ssize_t sent_v2s = sendto(sock, pktbuf_v2s, pkt_len_v2s, 0, (struct sockaddr *)&addr, sizeof(addr));
    ssize_t sent_v3 = sendto(sock, pktbuf_v3, pkt_len_v3, 0, (struct sockaddr *)&addr, sizeof(addr));

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 发送数据包:\n", timestamp(), host, port);
        fprintf(stderr, "[%s] [DEBUG]:   v1:  %s (%zd/%zu 字节)\n",
                timestamp(), sent_v1 >= 0 ? "成功" : "失败", sent_v1, pkt_len_v1);
        fprintf(stderr, "[%s] [DEBUG]:   v2:  %s (%zd/%zu 字节)\n",
                timestamp(), sent_v2 >= 0 ? "成功" : "失败", sent_v2, pkt_len_v2);
        fprintf(stderr, "[%s] [DEBUG]:   v2s: %s (%zd/%zu 字节)\n",
                timestamp(), sent_v2s >= 0 ? "成功" : "失败", sent_v2s, pkt_len_v2s);
        fprintf(stderr, "[%s] [DEBUG]:   v3:  %s (%zd/%zu 字节)\n",
                timestamp(), sent_v3 >= 0 ? "成功" : "失败", sent_v3, pkt_len_v3);
    }
    // 使用 gettimeofday 获得微秒级精度
    struct timeval start_tv, now_tv;
    gettimeofday(&start_tv, NULL);
    long timeout_ms = 800; // 800ms 总超时
    int responses_received = 0;
    int consecutive_empty = 0;
    long last_log_ms = 0;

    while (1)
    {
        gettimeofday(&now_tv, NULL);
        long elapsed_ms = (now_tv.tv_sec - start_tv.tv_sec) * 1000 +
                          (now_tv.tv_usec - start_tv.tv_usec) / 1000;

        // 每200ms输出一次进度
        if (verbose && elapsed_ms - last_log_ms >= 200)
        {
            fprintf(stderr, "[%s] [DEBUG]: %s:%d 等待响应... 已用时 %ldms (收到 %d 个响应)\n",
                    timestamp(), host, port, elapsed_ms, responses_received);
            last_log_ms = elapsed_ms;
        }

        if (elapsed_ms >= timeout_ms)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 达到超时时间 %ldms,停止等待\n", timestamp(), host, port, timeout_ms);
            }
            break;
        }

        // 如果已收到所有可能的响应,提前退出
        if (*v1_ok && *v2_ok && *v2s_ok && *v3_ok)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 所有版本响应已收到,提前退出\n", timestamp(), host, port);
            }
            break;
        }

        // 尝试接收数据
        ssize_t recv_len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);

        if (recv_len < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // 没有数据可读
                consecutive_empty++;
                if (consecutive_empty >= 5 && responses_received > 0)
                {
                    // 连续 5 次没数据且已收到至少一个响应,可能不会再有响应了
                    if (verbose)
                    {
                        fprintf(stderr, "[%s] [DEBUG]: %s:%d 连续 %d 次无数据,提前退出\n",
                                timestamp(), host, port, consecutive_empty);
                    }
                    break;
                }
                usleep(20000); // 等待 20ms
                continue;
            }
            else
            {
                // 其他错误
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d recvfrom() 错误: %s\n",
                            timestamp(), host, port, strerror(errno));
                }
                break;
            }
        }

        consecutive_empty = 0;
        responses_received++;

        // 根据响应内容判断版本
        if (recv_len >= 2 && !*v1_ok)
        {
            if (is_valid_v1_ack(recvbuf, recv_len))
            {
                *v1_ok = 1;
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测到 v1 响应：✓ 在线\n", timestamp(), host, port);
                }
                continue;
            }
            else if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 响应不是有效的 v1 ACK\n", timestamp(), host, port);
            }
        }

        if (recv_len >= 28 && !*v2_ok)
        {
            if (is_valid_v2_ack(recvbuf, recv_len, cookie_v2))
            {
                *v2_ok = 1;
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测到 v2 响应：✓ 在线\n", timestamp(), host, port);
                }
                continue;
            }
            else if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 响应不是有效的 v2 ACK\n", timestamp(), host, port);
            }
        }

        if (recv_len >= 28 && !*v2s_ok)
        {
            if (is_valid_v2s_ack(recvbuf, recv_len, cookie_v2s))
            {
                *v2s_ok = 1;
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测到 v2s 响应：✓ 在线\n", timestamp(), host, port);
                }
                continue;
            }
            else if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 响应不是有效的 v2s ACK\n", timestamp(), host, port);
            }
        }

        if (recv_len >= 28 && !*v3_ok)
        {
            if (is_valid_v3_ack(recvbuf, recv_len, cookie_v3))
            {
                *v3_ok = 1;
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测到 v3 响应：✓ 在线\n", timestamp(), host, port);
                }
                continue;
            }
            else if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 响应不是有效的 v3 ACK\n", timestamp(), host, port);
            }
        }
    }

    close(sock);
    // 输出最终检测结果
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测完成 - v1:%s v2:%s v2s:%s v3:%s\n",
                timestamp(), host, port,
                *v1_ok ? "✓" : "✗",
                *v2_ok ? "✓" : "✗",
                *v2s_ok ? "✓" : "✗",
                *v3_ok ? "✓" : "✗");
    }
    // 如果所有版本都失败,输出诊断信息
    if (!*v1_ok && !*v2_ok && !*v2s_ok && !*v3_ok)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: %s:%d 未收到任何响应,主机不可达?端口关闭?被过滤?\n",
                    timestamp(), host, port);
            fprintf(stderr, "[%s] [DEBUG]: %s:%d 诊断信息:\n", timestamp(), host, port);
            fprintf(stderr, "[%s] [DEBUG]:   - 发送状态: v1=%s v2=%s v2s=%s v3=%s\n",
                    timestamp(),
                    sent_v1 >= 0 ? "成功" : "失败",
                    sent_v2 >= 0 ? "成功" : "失败",
                    sent_v2s >= 0 ? "成功" : "失败",
                    sent_v3 >= 0 ? "成功" : "失败");
            fprintf(stderr, "[%s] [DEBUG]:   - 收到的响应数: %d\n", timestamp(), responses_received);
            fprintf(stderr, "[%s] [DEBUG]:   - 超时时间: %ldms\n", timestamp(), timeout_ms);
        }
    }
    return (*v1_ok || *v2_ok || *v2s_ok || *v3_ok) ? 0 : -1;
}

// 加载历史记录
static void load_history(host_stats_t *host)
{
    char filename[512];
    snprintf(filename, sizeof(filename), "%s/%s_%d.dat", STATE_DIR, host->host, host->port);

    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: %s:%d 历史记录文件不存在: %s\n",
                    timestamp(), host->host, host->port, filename);
        }
        return;
    }

    fread(&host->history_index, sizeof(int), 1, f);
    fread(&host->history_count, sizeof(int), 1, f);
    fread(host->history, sizeof(check_record_t), MAX_HISTORY, f);
    fread(&host->total_checks, sizeof(int), 1, f);
    fread(&host->success_v1, sizeof(int), 1, f);
    fread(&host->success_v2, sizeof(int), 1, f);
    fread(&host->success_v2s, sizeof(int), 1, f);
    fread(&host->success_v3, sizeof(int), 1, f);

    fclose(f);
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 已加载历史记录: history_count=%d, total_checks=%d\n",
                timestamp(), host->host, host->port, host->history_count, host->total_checks);
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 累计成功: v1=%d, v2=%d, v2s=%d, v3=%d\n",
                timestamp(), host->host, host->port,
                host->success_v1, host->success_v2, host->success_v2s, host->success_v3);
    }
}

// 添加检测记录
static void add_check_record(host_stats_t *host, int success)
{
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 添加检测记录: success=%d, 当前 history_index=%d, history_count=%d\n",
                timestamp(), host->host, host->port, success, host->history_index, host->history_count);
    }
    host->history[host->history_index].timestamp = time(NULL);
    host->history[host->history_index].success = success;

    host->history_index = (host->history_index + 1) % MAX_HISTORY;
    if (host->history_count < MAX_HISTORY)
    {
        host->history_count++;
    }
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 记录已添加: 新 history_index=%d, history_count=%d\n",
                timestamp(), host->host, host->port, host->history_index, host->history_count);
    }
}

// 计算连通率
static float calculate_uptime(const host_stats_t *host)
{
    if (host->history_count == 0)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: %s:%d 无历史记录,连通率=0.0%%\n",
                    timestamp(), host->host, host->port);
        }
        return 0.0f;
    }

    int success_count = 0;
    for (int i = 0; i < host->history_count; i++)
    {
        if (host->history[i].success)
        {
            success_count++;
        }
    }

    float uptime = (float)success_count / host->history_count * 100.0f;

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 连通率计算: success_count=%d, history_count=%d, uptime=%.2f%%\n",
                timestamp(), host->host, host->port, success_count, host->history_count, uptime);
    }

    return uptime;
}

// 读取配置文件
static void load_config(const char *config_file)
{
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 开始读取配置文件: %s\n", timestamp(), config_file);
    }
    FILE *f = fopen(config_file, "r");
    if (!f)
    {
        fprintf(stderr, "[%s] [DEBUG]: 配置文件打开失败: %s\n", timestamp(), config_file);
        return;
    }

    char line[1024];
    int line_num = 0;
    while (fgets(line, sizeof(line), f) && g_state.host_count < MAX_HOSTS)
    {
        line_num++;
        // 跳过注释和空行
        if (line[0] == '#' || line[0] == '\n')
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 跳过第 %d 行 (注释或空行)\n", timestamp(), line_num);
            }
            continue;
        }

        char host[256] = {0};
        int port = 10086;
        char note[512] = {0};

        // 格式: host:port|note 或 host:port
        char *pipe = strchr(line, '|');
        if (pipe)
        {
            *pipe = '\0';
            strncpy(note, pipe + 1, sizeof(note) - 1);
            // 移除换行符
            char *newline = strchr(note, '\n');
            if (newline)
                *newline = '\0';
        }

        char *colon = strchr(line, ':');
        if (colon)
        {
            *colon = '\0';
            port = atoi(colon + 1);
        }
        strncpy(host, line, sizeof(host) - 1);

        host_stats_t *h = &g_state.hosts[g_state.host_count];
        strncpy(h->host, host, sizeof(h->host) - 1);
        h->port = port;
        strncpy(h->note, note, sizeof(h->note) - 1);
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 第 %d 行解析成功: host=%s, port=%d, note=%s\n",
                    timestamp(), line_num, host, port, note[0] ? note : "(无)");
        }

        load_history(h);
        g_state.host_count++;
    }

    fclose(f);
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 配置文件读取完成,共加载 %d 个主机\n",
                timestamp(), g_state.host_count);
    }
}

// 重新加载配置文件  
static void reload_config(void) {  
    if (g_state.config_file_path[0] == '\0') {  
        return;  // 没有配置文件  
    }  
      
    if (verbose) {  
        fprintf(stderr, "[%s] [DEBUG]: 检测到配置文件变化,开始重新加载\n", timestamp());  
    }  
      
    pthread_mutex_lock(&g_state.lock);  
      
    // 保存旧的主机数量  
    int old_count = g_state.host_count;  
      
    // 清空现有配置  
    g_state.host_count = 0;  
    memset(g_state.hosts, 0, sizeof(g_state.hosts));  
      
    pthread_mutex_unlock(&g_state.lock);  
      
    // 重新加载配置文件  
    load_config(g_state.config_file_path);  
      
    if (verbose) {  
        fprintf(stderr, "[%s] [DEBUG]: 配置重载完成: 旧主机数=%d, 新主机数=%d\n",  
                timestamp(), old_count, g_state.host_count);  
    }  
}

// 生成 HTML 页面
void generate_html(char *buf, size_t bufsize)
{
    // 如果开启详细模式，输出调试信息（中文注释）
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 开始生成 HTML 页面\n", timestamp());
    }
    pthread_mutex_lock(&g_state.lock);

    time_t now = time(NULL);
    time_t uptime = now - g_state.start_time;

    // 智能格式化运行时间（中文注释）
    char uptime_str[256] = "";
    int has_content = 0;

    // 计算各个时间单位
    int years = uptime / (365 * 24 * 3600);
    uptime %= (365 * 24 * 3600);

    int months = uptime / (30 * 24 * 3600);
    uptime %= (30 * 24 * 3600);

    int weeks = uptime / (7 * 24 * 3600);
    uptime %= (7 * 24 * 3600);

    int days = uptime / (24 * 3600);
    uptime %= (24 * 3600);

    int hours = uptime / 3600;
    uptime %= 3600;

    int minutes = uptime / 60;
    int seconds = uptime % 60;

    // 只显示有值的单位
    if (years > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%d年", years);
        has_content = 1;
    }
    if (months > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d月", has_content ? " " : "", months);
        has_content = 1;
    }
    if (weeks > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d周", has_content ? " " : "", weeks);
        has_content = 1;
    }
    if (days > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d天", has_content ? " " : "", days);
        has_content = 1;
    }
    if (hours > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d时", has_content ? " " : "", hours);
        has_content = 1;
    }
    if (minutes > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d分", has_content ? " " : "", minutes);
        has_content = 1;
    }
    if (seconds > 0 || !has_content)
    { // 如果所有单位都是0,至少显示秒
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d秒", has_content ? " " : "", seconds);
    }

    // 找到最近的检测时间
    time_t last_update = 0;
    for (int i = 0; i < g_state.host_count; i++)
    {
        if (g_state.hosts[i].last_check > last_update)
        {
            last_update = g_state.hosts[i].last_check;
        }
    }

    // 如果没有检测记录,使用启动时间
    if (last_update == 0)
    {
        last_update = g_state.start_time;
    }

    // 转换为中国时间
    struct tm *tm_info = localtime(&last_update);
    char time_str[128];
    strftime(time_str, sizeof(time_str), "%Y年%m月%d日 %H时%M分%S秒", tm_info);

    // 页面刷新间隔等于检测间隔(秒)
    int refresh_seconds = g_state.check_interval_minutes * 60;

    int len = snprintf(buf, bufsize,
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: text/html; charset=utf-8\r\n"
                       "Connection: close\r\n\r\n"
                       "<!DOCTYPE html>\n"
                       "<html lang='zh-CN'><head>\n"
                       "<meta charset='utf-8'>\n"
                       "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
                       "<meta http-equiv='refresh' content='%d'>\n"
                       "<title>N2N Supernode Status</title>\n"
                       "<link rel='icon' type='image/svg+xml' href='data:image/svg+xml,<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 48 48\"><defs><linearGradient id=\"g\" x1=\"0%%\" y1=\"0%%\" x2=\"100%%\" y2=\"100%%\"><stop offset=\"0%%\" style=\"stop-color:rgb(124,58,237)\"/><stop offset=\"100%%\" style=\"stop-color:rgb(6,182,212)\"/></linearGradient></defs><rect width=\"48\" height=\"48\" rx=\"10\" fill=\"url(%%23g)\"/><text x=\"24\" y=\"32\" font-family=\"Inter,sans-serif\" font-size=\"18\" font-weight=\"700\" fill=\"white\" text-anchor=\"middle\">N2N</text></svg>'>\n"
                       "<style>\n"
                       "/* 浅色主题 */\n"
                       ":root{\n"
                       "  --bg:#f8f9fa;\n"
                       "  --card:#ffffff;\n"
                       "  --text:#1f2937;\n"
                       "  --muted:#6b7280;\n"
                       "  --accent:#7c3aed;\n"
                       "  --accent-2:#06b6d4;\n"
                       "  --success:#22c55e;\n"
                       "  --danger:#ef4444;\n"
                       "  --border:#e5e7eb;\n"
                       "  --radius:12px;\n"
                       "}\n"
                       "html,body{height:100%%;margin:0;padding:0;}\n"
                       "body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; background: var(--bg); color: var(--text); -webkit-font-smoothing:antialiased; }\n"
                       ".container{max-width:1200px;margin:28px auto;padding:20px;}\n"
                       "header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px;flex-wrap:wrap;}\n"
                       ".brand{display:flex;gap:12px;align-items:center}\n"
                       ".logo{width:48px;height:48px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:flex;align-items:center;justify-content:center;font-weight:700;color:white;box-shadow: 0 4px 12px rgba(124,58,237,0.25);}\n"
                       "h1{font-size:20px;margin:0;color:var(--text)}\n"
                       ".sub{color:var(--muted);font-size:13px}\n"
                       ".card{background:var(--card);border-radius:var(--radius);padding:14px;box-shadow: 0 2px 8px rgba(0,0,0,0.08);border:1px solid var(--border)}\n"
                       ".stats{display:flex;gap:12px;flex-wrap:wrap;align-items:center;}\n"
                       ".stat{padding:8px 16px;border-radius:8px;background:#f9fafb;border:1px solid var(--border);}\n"
                       ".stat h3{margin:0;font-size:12px;color:var(--muted);font-weight:500;}\n"
                       ".stat p{margin:4px 0 0;font-size:16px;font-weight:600;color:var(--text);}\n"
                       ".top-notice{margin-bottom:12px;padding:12px;border-radius:10px;display:flex;align-items:center;gap:12px;justify-content:space-between;transition:all 300ms ease;}\n"
                       ".notice-ok{background:#f0fdf4;border:1px solid #86efac;color:#166534}\n"
                       ".notice-warn{background:#fef2f2;border:1px solid #fca5a5;color:#991b1b}\n"
                       ".notice-left{display:flex;align-items:center;gap:12px}\n"
                       ".notice-dot{width:12px;height:12px;border-radius:50%%;}\n"
                       ".notice-btn{background:transparent;border:none;color:inherit;font-weight:600;cursor:pointer;padding:8px 12px;border-radius:8px;text-decoration:underline;}\n"
                       ".filter-section{display:flex;gap:12px;align-items:center;flex-wrap:wrap}\n"
                       "select,button{background:white;border:1px solid var(--border);padding:8px 10px;border-radius:8px;color:var(--text);cursor:pointer;}\n"
                       "select:hover,button:hover{border-color:var(--accent);}\n"
                       ".table-wrap{overflow:auto;border-radius:12px;margin-top:12px;}\n"
                       "table{width:100%%;min-width:700px;border-collapse:collapse;background:var(--card);color:var(--text);}\n"
                       "thead th{position:sticky;top:0;background:var(--card);backdrop-filter: blur(6px);padding:12px;text-align:center;font-size:15px;font-weight:700;border-bottom:2px solid var(--border);}\n"
                       "thead th.sortable{cursor:pointer;user-select:none;}\n"
                       "thead th.sortable:hover{background:#f9fafb;}\n"
                       "thead th.sortable::after{content:' ⇅';opacity:0.4;font-size:11px;}\n"
                       "thead th.sort-asc::after{content:' ↑';opacity:1;color:var(--accent);}\n"
                       "thead th.sort-desc::after{content:' ↓';opacity:1;color:var(--accent);}\n"
                       "tbody td{padding:12px;border-bottom:1px solid #f3f4f6;vertical-align:middle;text-align:center;}\n"
                       "tr:hover td{background:#f9fafb;}\n"
                       ".host-cell{color:var(--accent-2);cursor:pointer;text-decoration:underline;font-weight:500;}\n"
                       ".version-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;margin:2px;}\n"
                       ".badge-v1{background:#f3e8ff;color:#7c3aed;border:1px solid #e9d5ff;}\n"
                       ".badge-v2{background:#e0f2fe;color:#0284c7;border:1px solid #bae6fd;}\n"
                       ".badge-v2s{background:#dbeafe;color:#0369a1;border:1px solid #bfdbfe;}\n"
                       ".badge-v3{background:#fef3c7;color:#d97706;border:1px solid #fde68a;}\n"
                       ".badge-unknown{background:#f3f4f6;color:var(--muted);border:1px solid #e5e7eb;}\n"
                       ".status-online{color:var(--success);font-weight:700}\n"
                       ".status-offline{color:var(--danger);font-weight:700}\n"
                       ".progress-container{width:100%%;background:#f0f0f0;border-radius:10px;overflow:hidden;height:24px;position:relative;}\n"
                       ".progress-bar-bg{position:absolute;left:0;top:0;height:100%%;transition:width 0.3s ease;min-width:100%%;}\n"                                                                                // 添加 min-width:100%%  // 新增背景层
                       ".progress-bar-text{position:absolute;left:0;top:0;width:100%%;height:100%%;display:flex;align-items:center;justify-content:center;color:white;font-size:12px;font-weight:700;z-index:1;}\n" // 新增文字层
                       ".tooltip{position:fixed;background:rgba(31,41,55,0.95);color:white;padding:10px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,0.2);z-index:1001;pointer-events:none;max-width:320px;transform:translateY(6px);opacity:0;transition:opacity 180ms ease,transform 180ms ease}\n"
                       ".tooltip.show{opacity:1;transform:translateY(0)}\n"
                       ".tooltip-title{font-weight:700;margin-bottom:6px;}\n"
                       ".tooltip-history{display:flex;gap:4px;flex-wrap:wrap;max-height:60px;overflow:hidden;max-width:250px;}\n" // 添加 max-width
                       ".history-bar{width:8px;height:28px;border-radius:2px;flex-shrink:0;}\n"                                   // 添加 flex-shrink:0
                       ".history-online{background:var(--success)}\n"
                       ".history-offline{background:var(--danger)}\n"
                       ".modal-overlay{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,0.5);backdrop-filter:blur(4px);z-index:2000}\n"
                       ".modal-overlay.active{display:flex}\n"
                       ".modal-content{background:white;border-radius:12px;padding:20px;max-width:760px;width:92%%;max-height:86vh;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,0.3);}\n"
                       ".modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;padding-bottom:12px;border-bottom:2px solid var(--border);flex-shrink:0;}\n"
                       ".modal-title{font-size:18px;font-weight:700;color:var(--text);}\n"
                       ".modal-close{background:transparent;border:none;color:var(--muted);font-size:24px;cursor:pointer;width:32px;height:32px;border-radius:50%%;display:flex;align-items:center;justify-content:center;}\n"
                       ".modal-close:hover{background:#f3f4f6;color:var(--text);}\n"
                       ".history-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(80px,1fr));gap:12px;margin-top:12px;overflow-y:auto;flex:1;}\n"
                       ".history-item{background:#f9fafb;padding:10px;border-radius:8px;text-align:center;border:1px solid var(--border);transition:all 0.2s;}\n"
                       ".history-item:hover{background:#f3f4f6;transform:translateY(-2px);box-shadow:0 4px 8px rgba(0,0,0,0.1);}\n"
                       ".history-item-bar{width:44px;height:44px;border-radius:8px;margin:0 auto 8px;}\n"
                       ".history-item-time{font-size:11px;color:var(--muted);line-height:1.4;}\n"
                       ".history-item-date{font-weight:600;color:var(--text);}\n"
                       ".toast{position:fixed;top:18px;right:18px;color:white;padding:12px 16px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.3);z-index:1002;font-weight:600;font-size:14px;transform:translateX(400px);opacity:0;transition:transform 0.3s cubic-bezier(0.68,-0.55,0.265,1.55),opacity 0.3s ease;}\n"
                       ".toast.show{transform:translateX(0);opacity:1;}\n"
                       ".toast.hide{transform:translateX(400px);opacity:0;}\n"
                       ".toast-success{background:rgba(34,197,94,0.95);}\n"
                       ".toast-error{background:rgba(239,68,68,0.95);}\n"
                       "::-webkit-scrollbar{width:8px;height:8px;}\n"
                       "::-webkit-scrollbar-track{background:#f1f1f1;border-radius:10px;}\n"
                       "::-webkit-scrollbar-thumb{background:#888;border-radius:10px;}\n"
                       "::-webkit-scrollbar-thumb:hover{background:#555;}\n"
                       ".footer{margin-top:40px;padding:20px;text-align:center;border-top:1px solid var(--border);color:var(--muted);font-size:14px;}\n"  
			".footer a{color:var(--accent);text-decoration:none;font-weight:600;}\n"  
			".footer a:hover{text-decoration:underline;}\n"
                       "@keyframes blink-red {\n"
                       "  0%%, 100%% { background-color: transparent; }\n"
                       "  50%% { background-color: #fee2e2; }\n" // 浅红色
                       "}\n"
                       ".blink-highlight {\n"
                       "  animation: blink-red 0.6s ease-in-out 5;\n" // 闪烁5次
                       "}\n"
                       "@media (max-width:900px){.container{padding:12px}.stat{min-width:auto;padding:6px 12px;}.host-cell{font-size:14px}.progress-container{height:20px}.history-item-bar{width:36px;height:36px}}\n"
                       "@media (max-width:640px){thead th{font-size:12px;padding:8px;}tbody td{padding:8px;}table{min-width:640px}}\n"
                       "@media (prefers-reduced-motion: reduce){*{transition:none!important}}\n"
                       "</style>\n"
                       "<script>\n"
                       "var sortOrder = 0;\n"
                       "function filterTable() {\n"
                       "  var versionFilter = document.getElementById('versionFilter').value;\n"
                       "  var statusFilter = document.getElementById('statusFilter').value;\n"
                       "  var table = document.getElementById('hostTable');\n"
                       "  var rows = table.getElementsByTagName('tr');\n"
                       "  for (var i = 1; i < rows.length; i++) {\n"
                       "    var row = rows[i];\n"
                       "    var versionCell = row.cells[2].textContent;\n"
                       "    var statusCell = row.cells[4].textContent;\n"
                       "    var showVersion = (versionFilter === 'all' || versionCell.includes(versionFilter));\n"
                       "    var showStatus = (statusFilter === 'all' || \n"
                       "                     (statusFilter === 'online' && statusCell.includes('在线')) ||\n"
                       "                     (statusFilter === 'offline' && statusCell.includes('离线')));\n"
                       "    row.style.display = (showVersion && showStatus) ? '' : 'none';\n"
                       "  }\n"
                       "  // 更新顶部通知栏（筛选后也更新计数）\n"
                       "  updateTopNotice();\n"
                       "}\n"
                       "function copyToClipboard(text) {\n"
                       "  if (navigator.clipboard && window.isSecureContext) {\n"
                       "    navigator.clipboard.writeText(text).then(function() {\n"
                       "      showToast('已将 ' + text + ' 复制到剪贴板', true);\n" // 成功:true
                       "    }).catch(function() {\n"
                       "      fallbackCopy(text);\n"
                       "    });\n"
                       "  } else {\n"
                       "    fallbackCopy(text);\n"
                       "  }\n"
                       "}\n"
                       "function fallbackCopy(text) {\n"
                       "  var textArea = document.createElement('textarea');\n"
                       "  textArea.value = text;\n"
                       "  textArea.style.position = 'fixed';\n"
                       "  textArea.style.left = '-999999px';\n"
                       "  document.body.appendChild(textArea);\n"
                       "  textArea.focus();\n"
                       "  textArea.select();\n"
                       "  try {\n"
                       "    document.execCommand('copy');\n"
                       "    showToast('已将 ' + text + ' 复制到剪贴板', true);\n" // 成功:true
                       "  } catch (err) {\n"
                       "    showToast('复制失败,请手动复制', false);\n" // 失败:false
                       "  }\n"
                       "  document.body.removeChild(textArea);\n"
                       "}\n"
                       "function showToast(message, isSuccess) {\n"
                       "  var toast = document.createElement('div');\n"
                       "  toast.className = 'toast ' + (isSuccess ? 'toast-success' : 'toast-error');\n"
                       "  toast.textContent = message;\n"
                       "  document.body.appendChild(toast);\n"
                       "  \n"
                       "  // 触发弹出动画\n"
                       "  setTimeout(function() {\n"
                       "    toast.classList.add('show');\n"
                       "  }, 10);\n"
                       "  \n"
                       "  // 2秒后触发缩入动画\n"
                       "  setTimeout(function() {\n"
                       "    toast.classList.remove('show');\n"
                       "    toast.classList.add('hide');\n"
                       "    // 动画结束后移除元素\n"
                       "    setTimeout(function() {\n"
                       "      try { document.body.removeChild(toast); } catch(e) {}\n"
                       "    }, 300);\n"
                       "  }, 2000);\n"
                       "}\n"
                       "function sortByUptime() {\n"
                       "  var table = document.getElementById('hostTable');\n"
                       "  var tbody = table.getElementsByTagName('tbody')[0];\n"
                       "  var rows = Array.from(tbody.getElementsByTagName('tr'));\n"
                       "  sortOrder = sortOrder === 1 ? -1 : 1;\n"
                       "  rows.sort(function(a, b) {\n"
                       "    var uptimeA = parseFloat(a.cells[3].textContent);\n"
                       "    var uptimeB = parseFloat(b.cells[3].textContent);\n"
                       "    return sortOrder * (uptimeA - uptimeB);\n"
                       "  });\n"
                       "  rows.forEach(function(row) { tbody.appendChild(row); });\n"
                       "  var header = table.getElementsByTagName('th')[3];\n"
                       "  header.className = 'sortable ' + (sortOrder === 1 ? 'sort-asc' : 'sort-desc');\n"
                       "}\n"
                       "var tooltip = null;\n"
                       "function showHistoryTooltip(event, historyData) {\n"
                       "  if (!tooltip) {\n"
                       "    tooltip = document.createElement('div');\n"
                       "    tooltip.className = 'tooltip';\n"
                       "    document.body.appendChild(tooltip);\n"
                       "  }\n"
                       "  var html = '<div class=\"tooltip-title\">最近检测记录</div>';\n"
                       "  html += '<div class=\"tooltip-history\">';\n"
                       "  var records = historyData.split(',');\n"
                       "  var maxDisplay = 60; // 显示最近60个(两行,每行30个)\n"
                       "  var startIdx = Math.max(0, records.length - maxDisplay);\n"
                       "  for (var i = startIdx; i < records.length; i++) {\n"
                       "    var parts = records[i].split(':');\n"
                       "    if (parts.length >= 2) {\n"
                       "      var status = parts[1] === '1' ? 'history-online' : 'history-offline';\n"
                       "      html += '<div class=\"history-bar ' + status + '\"></div>';\n"
                       "    }\n"
                       "  }\n"
                       "  html += '</div>';\n"
                       "  tooltip.innerHTML = html;\n"
                       "  tooltip.classList.add('show');\n"
                       "  var left = event.pageX + 12;\n"
                       "  var top = event.pageY + 12;\n"
                       "  if (left + 340 > window.innerWidth) left = window.innerWidth - 340 - 12;\n"
                       "  if (top + 100 > window.innerHeight) top = window.innerHeight - 100 - 12;\n" // 调整高度检测
                       "  tooltip.style.left = left + 'px';\n"
                       "  tooltip.style.top = top + 'px';\n"
                       "}\n"
                       // 新增模态窗口函数（中文注释）
                       "function showHistoryModal(host, port, historyData) {\n"
                       "  var modal = document.getElementById('historyModal');\n"
                       "  if (!modal) {\n"
                       "    modal = document.createElement('div');\n"
                       "    modal.id = 'historyModal';\n"
                       "    modal.className = 'modal-overlay';\n"
                       "    document.body.appendChild(modal);\n"
                       "  }\n"
                       "  \n"
                       "  var html = '<div class=\"modal-content\" onclick=\"event.stopPropagation()\">';\n"
                       "  html += '<div class=\"modal-header\">';\n"
                       "  html += '<div class=\"modal-title\">' + host + ':' + port + ' 历史检测记录</div>';\n"
                       "  html += '<button class=\"modal-close\" onclick=\"closeHistoryModal()\">×</button>';\n"
                       "  html += '</div>';\n"
                       "  html += '<div class=\"history-grid\">';\n"
                       "  \n"
                       "  var records = historyData.split(',');\n"
                       "  var uniqueRecords = {};\n"
                       "  var sortedRecords = [];\n"
                       "  \n"
                       "  // 去重并收集记录\n"
                       "  for (var i = 0; i < records.length; i++) {\n"
                       "    var parts = records[i].split(':');\n"
                       "    if (parts.length >= 2) {\n"
                       "      var timestamp = parseInt(parts[0]);\n"
                       "      if (!uniqueRecords[timestamp]) {\n"
                       "        uniqueRecords[timestamp] = parts[1];\n"
                       "        sortedRecords.push({timestamp: timestamp, status: parts[1] === '1'});\n"
                       "      }\n"
                       "    }\n"
                       "  }\n"
                       "  \n"
                       "  // 按时间戳排序(从新到旧)\n"
                       "  sortedRecords.sort(function(a, b) { return b.timestamp - a.timestamp; });\n"
                       "  \n"
                       "  // 生成 HTML\n"
                       "  for (var i = 0; i < sortedRecords.length; i++) {\n"
                       "    var record = sortedRecords[i];\n"
                       "    var date = new Date(record.timestamp * 1000);\n"
                       "    var dateStr = (date.getMonth() + 1) + '/' + date.getDate();\n"
                       "    var timeStr = date.getHours().toString().padStart(2, '0') + ':' + date.getMinutes().toString().padStart(2, '0');\n"
                       "    \n"
                       "    // 生成完整时间字符串用于 title\n"
                       "    var fullDateStr = date.getFullYear() + '/' + \n"
                       "                      (date.getMonth() + 1).toString().padStart(2, '0') + '/' + \n"
                       "                      date.getDate().toString().padStart(2, '0') + ' ' +\n"
                       "                      date.getHours().toString().padStart(2, '0') + ':' + \n"
                       "                      date.getMinutes().toString().padStart(2, '0') + ':' + \n"
                       "                      date.getSeconds().toString().padStart(2, '0');\n"
                       "    var statusText = record.status ? '在线' : '离线';\n"
                       "    \n"
                       "    html += '<div class=\"history-item\" title=\"' + fullDateStr + ' ' + statusText + '\">';\n"
                       "    html += '<div class=\"history-item-bar ' + (record.status ? 'online' : 'offline') + '\" style=\"background:' + (record.status ? 'linear-gradient(90deg,#34d399,#10b981)' : 'linear-gradient(90deg,#fb7185,#ef4444)') + '\"></div>';\n"
                       "    html += '<div class=\"history-item-time\">';\n"
                       "    html += '<div class=\"history-item-date\">' + dateStr + '</div>';\n"
                       "    html += '<div>' + timeStr + '</div>';\n"
                       "    html += '</div>';\n"
                       "    html += '</div>';\n"
                       "  }\n"
                       "  \n"
                       "  html += '</div></div>';\n"
                       "  modal.innerHTML = html;\n"
                       "  modal.className = 'modal-overlay active';\n"
                       "  \n"
                       "  // 点击背景关闭\n"
                       "  modal.onclick = function() { closeHistoryModal(); };\n"
                       "}\n"
                       "\n"
                       "function closeHistoryModal() {\n"
                       "  var modal = document.getElementById('historyModal');\n"
                       "  if (modal) {\n"
                       "    modal.className = 'modal-overlay';\n"
                       "  }\n"
                       "}\n"
                       "\n"
                       "// 隐藏悬浮提示\n"
                       "function hideHistoryTooltip() {\n"
                       "  if (tooltip) tooltip.classList.remove('show');\n"
                       "}\n"
                       "\n"
                       "// 页面加载完成后：初始化筛选、计算并显示顶部通知栏（中文注释）\n"
                       "function updateTopNotice(){\n"
                       "  var rows = document.getElementById('hostTable').getElementsByTagName('tr');\n"
                       "  var total = 0; var offline = 0;\n"
                       "  var firstOfflineHost = null;\n" // 记录第一个离线主机
                       "  var firstOfflinePort = null;\n"
                       "  for (var i=1;i<rows.length;i++){\n"
                       "    if (rows[i].style.display === 'none') continue;\n"
                       "    total++;\n"
                       "    var s = rows[i].cells[4].textContent || '';\n"
                       "    if (s.indexOf('离线') !== -1) {\n"
                       "      offline++;\n"
                       "      if (!firstOfflineHost) {\n" // 记录第一个离线主机
                       "        firstOfflineHost = rows[i].cells[0].textContent;\n"
                       "        firstOfflinePort = rows[i].cells[1].textContent;\n"
                       "      }\n"
                       "    }\n"
                       "  }\n"
                       "  var noticeEl = document.getElementById('topNotice');\n"
                       "  if (!noticeEl) return;\n"
                       "  if (offline > 0) {\n"
                       "    noticeEl.className = 'top-notice card notice-warn';\n"
                       "    noticeEl.innerHTML = '<div class=\"notice-left\"><div class=\"notice-dot\" style=\"background:linear-gradient(90deg,#fb7185,#ef4444)\"></div><div><div style=\"font-weight:800\">存在异常服务</div><div class=\"sub\">发现 '+offline+' 个服务异常，请尽快检查</div></div></div><div><button class=\"notice-btn\" onclick=\"scrollToHost(\\''+firstOfflineHost+'\\', '+firstOfflinePort+')\">查看详情</button></div>';\n"
                       "  } else {\n"
                       "    noticeEl.className = 'top-notice card notice-ok';\n"
                       "    noticeEl.innerHTML = '<div class=\"notice-left\"><div class=\"notice-dot\" style=\"background:linear-gradient(90deg,#34d399,#10b981)\"></div><div><div style=\"font-weight:800\">所有服务状态正常</div><div class=\"sub\">当前 '+total+' 个服务全部在线</div></div></div><div></div>';\n"
                       "  }\n"
                       "}\n"
                       "function scrollToTable(){ var el = document.querySelector('.table-wrap'); if(el) el.scrollIntoView({behavior:'smooth',block:'start'}); }\n"
                       "\n"
                       "function scrollToHost(host, port) {\n"
                       "  var rowId = 'host-' + host.replace(/\\./g, '-') + '-' + port;\n" // 替换点号为连字符
                       "  var row = document.getElementById(rowId);\n"
                       "  if (!row) return;\n"
                       "  \n"
                       "  // 滚动到目标行\n"
                       "  row.scrollIntoView({ behavior: 'smooth', block: 'center' });\n"
                       "  \n"
                       "  // 添加闪烁动画\n"
                       "  setTimeout(function() {\n"
                       "    row.classList.add('blink-highlight');\n"
                       "    setTimeout(function() {\n"
                       "      row.classList.remove('blink-highlight');\n"
                       "    }, 3000);  // 5次闪烁 × 0.6秒 = 3秒\n"
                       "  }, 500);  // 等待滚动完成\n"
                       "}\n"
                       "document.addEventListener('keydown', function(e) {\n"
                       "  if (e.key === 'Escape') closeHistoryModal();\n"
                       "});\n"
                       "\n"
                       "document.addEventListener('DOMContentLoaded', function(){\n"
                       "  // 初始化：更新顶部通知（页面生成的表格会包含状态类名）\n"
                       "  updateTopNotice();\n"
                       "  // 为所有进度条添加动画初始宽度（让其从0动画到目标值）\n"
                       "  var bars = document.querySelectorAll('.progress-bar');\n"
                       "  bars.forEach(function(bar){ var w = bar.getAttribute('data-target') || bar.style.width; bar.style.width = '0%%'; setTimeout(function(){ bar.style.width = w; }, 80); });\n"
                       "});\n"
                       "</script>\n"
                       "</head><body>\n"
                       "<div class='container'>\n"
                       "<header>\n"
                       "<div class='brand'>\n"
                       "<div class='logo'>N2N</div>\n"
                       "<div>\n"
                       "<h1>Supernode Status</h1>\n"
                       "<div class='sub'>展示实时连通性与历史检测记录</div>\n"
                       "</div>\n"
                       "</div>\n"
                       "<div class='stats'>\n"
                       "</div>\n"
                       "</header>\n"
                       "\n"
                       "<div id='topNotice' class='top-notice card'></div>\n"
                       "\n"
                       "<div class='card'>\n"
                       "<div style='display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap'>\n"
                       "<div style='display:flex;gap:12px;flex-wrap:wrap;'>\n" // 左侧容器
                       "<div class='stat'>\n"
                       "<h3>运行时间</h3>\n"
                       "<p>%s</p>\n"
                       "</div>\n"
                       "<div class='stat'>\n"
                       "<h3>检测间隔</h3>\n"
                       "<p>%d 分钟</p>\n"
                       "</div>\n"
                       "<div class='stat'>\n"
                       "<h3>最后检测</h3>\n"
                       "<p>%s</p>\n"
                       "</div>\n"
                       "</div>\n" // 关闭左侧容器
                       "<div class='filter-section'>\n"
                       "<label>版本筛选:</label>\n"
                       "<select id='versionFilter' onchange='filterTable()'>\n"
                       "<option value='all'>全部</option>\n"
                       "<option value='v1'>v1</option>\n"
                       "<option value='v2'>v2</option>\n"
                       "<option value='v2s'>v2s</option>\n"
                       "<option value='v3'>v3</option>\n"
                       "<option value='未知'>未知</option>\n"
                       "</select>\n"
                       "<label style='margin-left:20px'>状态筛选:</label>\n"
                       "<select id='statusFilter' onchange='filterTable()'>\n"
                       "<option value='all'>全部</option>\n"
                       "<option value='online'>在线</option>\n"
                       "<option value='offline'>离线</option>\n"
                       "</select>\n"
                       "</div>\n"
                       "</div>\n"
                       "</div>\n"
                       "\n"
                       "<div class='table-wrap card' style='margin-top:14px'>\n"
                       "<table id='hostTable' aria-label='主机列表'>\n"
                       "<thead><tr><th>主机</th><th>端口</th><th>版本</th><th class='sortable' onclick='sortByUptime()'>连通率</th><th>状态</th><th>最后检测</th><th>备注</th></tr></thead>\n"
                       "<tbody>\n",
                       refresh_seconds,
                       uptime_str,
                       g_state.check_interval_minutes,
                       time_str);

    // 注意：下面保留原有遍历逻辑与字段，但为了让前端的进度条动画更平滑，增加 data-target 属性并保持原有 class 名称与文本内容不变（中文注释）
    for (int i = 0; i < g_state.host_count; i++)
    {
        if (len >= bufsize - 2000)
            break;

        host_stats_t *h = &g_state.hosts[i];
        // 创建安全的主机 ID(将点号替换为连字符)
        char safe_host_id[512];
        strncpy(safe_host_id, h->host, sizeof(safe_host_id) - 1);
        safe_host_id[sizeof(safe_host_id) - 1] = '\0';
        for (char *p = safe_host_id; *p; p++)
        {
            if (*p == '.')
                *p = '-';
        }

        // 构建版本徽章
        char version_badges[256] = "";
        int has_any_version = 0;

        if (h->success_v1 > 0)
        {
            strcat(version_badges, "<span class='version-badge badge-v1'>v1</span>");
            has_any_version = 1;
        }
        if (h->success_v2 > 0)
        {
            strcat(version_badges, "<span class='version-badge badge-v2'>v2</span>");
            has_any_version = 1;
        }
        if (h->success_v2s > 0)
        {
            strcat(version_badges, "<span class='version-badge badge-v2s'>v2s</span>");
            has_any_version = 1;
        }
        if (h->success_v3 > 0)
        {
            strcat(version_badges, "<span class='version-badge badge-v3'>v3</span>");
            has_any_version = 1;
        }
        if (!has_any_version)
        {
            strcat(version_badges, "<span class='version-badge badge-unknown'>未知</span>");
        }

        // 计算该主机的连通率(基于历史记录)
        float overall_rate = calculate_uptime(h);

        // 转换最后检测时间
        char last_check_str[128] = "从未检测";
        if (h->last_check > 0)
        {
            time_t elapsed = now - h->last_check;
            if (elapsed < 60)
            {
                snprintf(last_check_str, sizeof(last_check_str), "%ld秒前", elapsed);
            }
            else if (elapsed < 3600)
            {
                snprintf(last_check_str, sizeof(last_check_str), "%ld分钟前", elapsed / 60);
            }
            else if (elapsed < 86400)
            {
                snprintf(last_check_str, sizeof(last_check_str), "%ld小时前", elapsed / 3600);
            }
            else
            {
                struct tm *last_tm = localtime(&h->last_check);
                strftime(last_check_str, sizeof(last_check_str), "%m月%d日 %H:%M", last_tm);
            }
        }

        // 确定状态 - 直接使用 last_status（保留原始数据结构与行为）
        const char *status_class = strstr(h->last_status, "在线") ? "status-online" : "status-offline";
        const char *status_text = h->last_status;

        // 构建历史记录数据字符串(用于悬浮提示和模态窗口)
        char history_data[4096] = "";
        if (h->history_count > 0)
        {
            // 从最旧的记录开始遍历(循环数组的正确顺序)
            int start_idx = (h->history_count < MAX_HISTORY) ? 0 : h->history_index;
            for (int j = 0; j < h->history_count; j++)
            {
                int idx = (start_idx + j) % MAX_HISTORY;
                char record[64];
                snprintf(record, sizeof(record), "%ld:%d%s",
                         h->history[idx].timestamp,
                         h->history[idx].success,
                         (j < h->history_count - 1) ? "," : "");
                strcat(history_data, record);
            }
        }

        // 计算整数百分比(去掉小数)
        int overall_rate_int = (int)(overall_rate + 0.5); // 四舍五入

        // 动态计算颜色 - 使用 HSL 色彩空间
        // 0% = hue 10 (红色), 100% = hue 90 (绿色)
        int hue = 10 + (int)(overall_rate * 0.8); // 0-100 映射到 10-90
        char gradient_bg[256];
        snprintf(gradient_bg, sizeof(gradient_bg),
                 "background:linear-gradient(90deg, hsl(%d, 90%%, 50%%), hsl(%d, 90%%, 40%%))",
                 hue, hue);

        len += snprintf(buf + len, bufsize - len,
                        "<tr id='host-%s-%d'>"
                        "<td class='host-cell' onclick='copyToClipboard(\"%s:%d\")'>%s</td>"
                        "<td>%d</td>"
                        "<td>%s</td>"
                        "<td onmouseenter='showHistoryTooltip(event, \"%s\")' "
                        "onmouseleave='hideHistoryTooltip()' "
                        "onclick='showHistoryModal(\"%s\", %d, \"%s\")' "
                        "style='cursor: pointer;'>"
                        "<div class='progress-container'>"
                        "<div class='progress-bar-bg' style='width: %d%%; %s'></div>" // 使用动态渐变背景
                        "<div class='progress-bar-text'>%d%%</div>"
                        "</div>"
                        "</td>"
                        "<td class='%s'>%s</td>"
                        "<td>%s</td>"
                        "<td>%s</td>"
                        "</tr>\n",
                        safe_host_id, h->port,
                        h->host, h->port, h->host,
                        h->port,
                        version_badges,
                        history_data,
                        h->host, h->port, history_data,
                        overall_rate_int, // 背景层宽度
                        gradient_bg,      // 动态渐变背景
                        overall_rate_int, // 文字显示
                        status_class, status_text,
                        last_check_str,
                        h->note[0] ? h->note : "-");
    }

    // 关闭 tbody、table 与页面结构（保留原结构，仅样式与脚本已现代化）
    len += snprintf(buf + len, bufsize - len,
                    "</tbody>\n"
                    "</table>\n"
                    "</div>\n"
                    "\n"
                    "<div class='footer'>\n"  
                    "© 2025 N2N Supernode Monitor · <a href='http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=GLULTq6IK_44qF_CAOSc4PqVLE_LMA6Y&authKey=KQ4hIgPoUa25xQF%%2FtFCNi%%2BuF31wob9vISoCpoOainpJ%%2Beo1AxRi%%2FZWmIImJbIZoH&noverify=0&group_code=196588661' target='_blank' rel='noopener noreferrer'>加入QQ群</a>\n"   
                    "</div>\n"  
                    "\n"
                    "</div>\n"
                    "</body></html>\n");

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: HTML 生成完成,总长度: %d 字节\n", timestamp(), len);
    }

    pthread_mutex_unlock(&g_state.lock);
}

static void save_history(const host_stats_t *host)
{
    // 确保目录存在
    struct stat st = {0};
    if (stat(STATE_DIR, &st) == -1)
    {
        if (mkdir(STATE_DIR, 0755) == -1)
        {
            fprintf(stderr, "[%s] [ERROR]: 无法创建目录 %s: %s\n", timestamp(), STATE_DIR, strerror(errno));
            return;
        }
    }

    char filename[512];
    snprintf(filename, sizeof(filename), "%s/%s_%d.dat", STATE_DIR, host->host, host->port);

    FILE *f = fopen(filename, "wb");
    if (!f)
    {
        fprintf(stderr, "[%s] [ERROR]: 无法写入检测记录文件 %s: %s\n", timestamp(), filename, strerror(errno));
        return;
    }

    fwrite(&host->history_index, sizeof(int), 1, f);
    fwrite(&host->history_count, sizeof(int), 1, f);
    fwrite(host->history, sizeof(check_record_t), MAX_HISTORY, f);
    fwrite(&host->total_checks, sizeof(int), 1, f);
    fwrite(&host->success_v1, sizeof(int), 1, f);
    fwrite(&host->success_v2, sizeof(int), 1, f);
    fwrite(&host->success_v2s, sizeof(int), 1, f);
    fwrite(&host->success_v3, sizeof(int), 1, f);

    fclose(f);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 已保存 %s:%d 的历史记录 (共 %d 条)\n",
                timestamp(), host->host, host->port, host->history_count);
    }
}

void generate_svg_response(int client_sock, int is_online, float uptime,       
                          int v1_ok, int v2_ok, int v2s_ok, int v3_ok) {    
    if (verbose) {      
        fprintf(stderr, "[%s] [DEBUG]: 开始生成 SVG 响应 (is_online=%d, uptime=%.2f%%, v1=%d, v2=%d, v2s=%d, v3=%d)\n",       
                timestamp(), is_online, uptime, v1_ok, v2_ok, v2s_ok, v3_ok);      
    }          
    char svg[4096];          
    int len = 0;          
              
    // HTTP 头          
    len += snprintf(svg + len, sizeof(svg) - len,          
        "HTTP/1.1 200 OK\r\n"          
        "Content-Type: image/svg+xml; charset=utf-8\r\n"          
        "Connection: close\r\n\r\n");          
          
    // 计算文字宽度（近似值）      
    const char *status_text = is_online ? "在线" : "离线";      
    int status_label_width = 32;      
    int status_value_width = 22;      
    int uptime_label_width = 44;      
    int uptime_value_width = uptime >= 100 ? 33 : (uptime >= 10 ? 28 : 23);     
        
    // 计算版本徽章宽度      
    int version_label_width = 32;      
    int version_count = v1_ok + v2_ok + v2s_ok + v3_ok;      
    int version_value_width = 0;      
    if (version_count > 0) {      
        version_value_width = version_count * 22 + (version_count - 1) * 2;      
    } else {      
        version_value_width = 28;      
    }    
      
    int badge_gap = 1;  // 徽章之间的间距  
    int status_total = status_label_width + status_value_width + 16;      
    int uptime_total = uptime >= 0 ? (uptime_label_width + uptime_value_width + 16) : 0;    
    int version_total = version_label_width + version_value_width + 16;       
    int total_width = status_total + (uptime_total > 0 ? uptime_total + badge_gap : 0) + version_total + badge_gap;     
        
    if (verbose) {    
        fprintf(stderr, "[%s] [DEBUG]: SVG 尺寸: status=%d, uptime=%d, version=%d, total=%d\n",    
                timestamp(), status_total, uptime_total, version_total, total_width);    
    }    
          
    // SVG 内容          
    len += snprintf(svg + len, sizeof(svg) - len,          
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"20\">\n",          
        total_width);      
            
    // ========== 状态徽章（独立，左右圆角）==========  
    const char *status_color = is_online ? "#4ade80" : "#ef4444";     
        
    if (verbose) {      
        fprintf(stderr, "[%s] [DEBUG]: 状态徽章颜色: %s (状态文字: %s)\n",      
                timestamp(), status_color, status_text);      
    }     
      
    // 状态徽章 - 左侧部分（左边圆角，右边直角）  
    len += snprintf(svg + len, sizeof(svg) - len,      
        "  <path d=\"M 5 0 L %d 0 L %d 20 L 3 20 Q 0 20 0 17 L 0 3 Q 0 0 5 0 Z\" fill=\"#555\"/>\n",      
        status_label_width + 8, status_label_width + 8);      
          
    // 状态徽章 - 右侧部分（左边直角，右边圆角）  
    int status_right = status_total - 5;  
    len += snprintf(svg + len, sizeof(svg) - len,      
        "  <path d=\"M %d 0 L %d 0 Q %d 0 %d 3 L %d 17 Q %d 20 %d 20 L %d 20 L %d 0 Z\" fill=\"%s\"/>\n",      
        status_label_width + 8, status_right, status_total, status_total,  
        status_total, status_total, status_right, status_label_width + 8, status_label_width + 8,  
        status_color);      
          
    // 状态徽章文字      
    int status_label_center = (status_label_width + 8) / 2;      
    int status_value_center = status_label_width + 8 + (status_total - status_label_width - 8) / 2;      
          
    len += snprintf(svg + len, sizeof(svg) - len,          
        "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">状态</text>\n"          
        "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">%s</text>\n",          
        status_label_center,      
        status_value_center,      
        status_text);          
              
    // ========== 连通率徽章（独立，左右圆角）==========  
    if (uptime >= 0) {        
        int hue = 10 + (int)(uptime * 0.8);      
        char uptime_color[32];        
        snprintf(uptime_color, sizeof(uptime_color), "hsl(%d, 90%%, 50%%)", hue);      
            
        if (verbose) {      
            fprintf(stderr, "[%s] [DEBUG]: 连通率徽章: uptime=%.2f%%, hue=%d, color=%s\n",      
                    timestamp(), uptime, hue, uptime_color);      
        }      
              
        int uptime_start = status_total + badge_gap;      
        int uptime_mid = uptime_start + uptime_label_width + 8;      
        int uptime_end = uptime_start + uptime_total;  
              
        // 连通率徽章 - 左侧部分（左边圆角，右边直角）  
        len += snprintf(svg + len, sizeof(svg) - len,      
            "  <path d=\"M %d 0 L %d 0 L %d 20 L %d 20 Q %d 20 %d 17 L %d 3 Q %d 0 %d 0 Z\" fill=\"#555\"/>\n",      
            uptime_start + 5, uptime_mid, uptime_mid, uptime_start + 5,  
            uptime_start, uptime_start, uptime_start, uptime_start, uptime_start + 5);      
              
        // 连通率徽章 - 右侧部分（左边直角，右边圆角）  
        int uptime_right = uptime_end - 5;  
        len += snprintf(svg + len, sizeof(svg) - len,      
            "  <path d=\"M %d 0 L %d 0 Q %d 0 %d 3 L %d 17 Q %d 20 %d 20 L %d 20 L %d 0 Z\" fill=\"%s\"/>\n",      
            uptime_mid, uptime_right, uptime_end, uptime_end,  
            uptime_end, uptime_end, uptime_right, uptime_mid, uptime_mid,  
            uptime_color);      
              
        // 连通率徽章文字    
        int uptime_label_center = uptime_start + (uptime_mid - uptime_start) / 2;      
        int uptime_value_center = uptime_mid + (uptime_end - uptime_mid) / 2;      
              
        len += snprintf(svg + len, sizeof(svg) - len,          
            "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">连通率</text>\n"          
            "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">%.0f%%</text>\n",          
            uptime_label_center,      
            uptime_value_center,      
            uptime);          
    }          
    if (is_online) {    
    // ========== 版本徽章（独立，左右圆角）==========  
    int version_start = status_total + (uptime_total > 0 ? uptime_total + badge_gap : 0) + badge_gap;      
    int version_mid = version_start + version_label_width + 8;      
    int version_end = version_start + version_total;      
        
    if (verbose) {    
        fprintf(stderr, "[%s] [DEBUG]: 版本徽章位置: start=%d, mid=%d, end=%d\n",    
                timestamp(), version_start, version_mid, version_end);    
    }    
         
    // 版本徽章 - 左侧部分（左边圆角，右边直角）      
    len += snprintf(svg + len, sizeof(svg) - len,      
        "  <path d=\"M %d 0 L %d 0 L %d 20 L %d 20 Q %d 20 %d 17 L %d 3 Q %d 0 %d 0 Z\" fill=\"#555\"/>\n",      
        version_start + 5, version_mid, version_mid, version_start + 5,  
        version_start, version_start, version_start, version_start, version_start + 5);   
        
    // 根据检测到的版本确定背景颜色  
    const char *version_bg_color;  
    if (version_count == 1) {  
        // 只检测到一个版本，使用对应颜色  
        if (v1_ok) {  
            version_bg_color = "#7c3aed";  // v1 紫色  
        } else if (v2_ok) {  
            version_bg_color = "#0284c7";  // v2 深蓝色  
        } else if (v2s_ok) {  
            version_bg_color = "#0369a1";  // v2s 中蓝色  
        } else {  // v3_ok  
            version_bg_color = "#d97706";  // v3 橙色  
        }  
    } else if (version_count > 1) {  
        // 检测到多个版本，使用红色  
        version_bg_color = "#ef4444";  
    } else {  
        // 未检测到任何版本，使用红色  
        version_bg_color = "#ef4444";  
    }    
          
    // 版本徽章 - 右侧部分（左边直角，右边圆角）- 使用动态背景颜色  
    int version_right = version_end - 5;    
    len += snprintf(svg + len, sizeof(svg) - len,        
        "  <path d=\"M %d 0 L %d 0 Q %d 0 %d 3 L %d 17 Q %d 20 %d 20 L %d 20 L %d 0 Z\" fill=\"%s\"/>\n",        
            version_mid, version_right, version_end, version_end,        
            version_end, version_end, version_right, version_mid, version_mid,  
            version_bg_color);  // 使用动态颜色      
          
    // 版本徽章文字      
    int version_label_center = version_start + (version_mid - version_start) / 2;      
    len += snprintf(svg + len, sizeof(svg) - len,      
        "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">版本</text>\n",      
    		version_label_center);      
          
    // 生成版本标签 
    if (version_count > 0) {      
        int x_offset = version_mid + 4;      
          
        if (v1_ok) {      
            len += snprintf(svg + len, sizeof(svg) - len,      
                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v1</text>\n",      
            	 x_offset + 5);     
            x_offset += 24;      
        }      
          
        if (v2_ok) {      
            len += snprintf(svg + len, sizeof(svg) - len,      
                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v2</text>\n",      
            	 x_offset + 5);     
            x_offset += 24;      
        }      
          
        if (v2s_ok) {      
            // v2s: 中蓝色背景 #0369a1  
            len += snprintf(svg + len, sizeof(svg) - len,      
                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v2s</text>\n",      
            	 x_offset + 6);      
            x_offset += 28;      
        }      
          
        if (v3_ok) {      
            // v3: 橙色背景 #d97706  
            len += snprintf(svg + len, sizeof(svg) - len,      
                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v3</text>\n",      
            	 x_offset + 5);     
        }      
    } else {      
        // 未知版本：使用红色背景 #ef4444  
        int version_value_center = version_mid + (version_value_width + 8) / 2;      
        len += snprintf(svg + len, sizeof(svg) - len,      
            "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">未知</text>\n",      
        	version_value_center);      
    }        
    }         
    len += snprintf(svg + len, sizeof(svg) - len, "</svg>\n");    
        
    if (verbose) {      
        fprintf(stderr, "[%s] [DEBUG]: SVG 生成完成，总长度: %d 字节\n", timestamp(), len);      
    }          
              
    send(client_sock, svg, len, 0);          
    close(client_sock);          
}
  
void send_error_response(int client_sock, const char *message) {  
    char response[512];  
    int len = snprintf(response, sizeof(response),  
        "HTTP/1.1 400 Bad Request\r\n"  
        "Content-Type: text/plain; charset=utf-8\r\n"  
        "Connection: close\r\n\r\n"  
        "%s", message);  
    send(client_sock, response, len, 0);  
    close(client_sock);  
}
void handle_api_request(int client_sock, const char *path) {  
    // 提取 supernode 参数  
    char *query = strchr(path, '?');  
    if (!query) {  
        close(client_sock);  
        return;  
    }  
      
    char supernode[512] = {0};  
    char *param = strstr(query, "supernode=");  
    if (!param) {
    	if (verbose) {  
            fprintf(stderr, "[%s] [DEBUG]: API请求缺少查询参数\n", timestamp());  
        }  
        close(client_sock);  
        return;  
    }
      
    // 解析参数值  
    sscanf(param + 10, "%511[^&]", supernode);  
    if (strlen(supernode) == 0) {  
    	if (verbose) {  
            fprintf(stderr, "[%s] [DEBUG]: API请求 supernode 参数为空\n", timestamp());  
        }
        close(client_sock);  
        return;  
    }  
       
    if (verbose) {  
        fprintf(stderr, "[%s] [DEBUG]: API请求解析到 supernode 参数: %s\n", timestamp(), supernode);  
    }
     
    // 验证格式: host:port  
    char host[256];  
    int port;  
    if (sscanf(supernode, "%255[^:]:%d", host, &port) != 2 ||   
        port <= 0 || port > 65535) { 
        if (verbose) {  
            fprintf(stderr, "[%s] [DEBUG]: API请求 supernode 参数值格式错误: %s\n", timestamp(), supernode);  
        } 
        send_error_response(client_sock, "格式错误,正确格式: host:port");  
        return;  
    }  
      
    // 执行检测  
    int v1_ok = 0, v2_ok = 0, v2s_ok = 0, v3_ok = 0;  
    int result = test_supernode_internal(host, port, &v1_ok, &v2_ok, &v2s_ok, &v3_ok); 
    
    if (verbose) {  
        fprintf(stderr, "[%s] [DEBUG]: API请求 %s:%d 检测结果: result=%d, v1=%d, v2=%d, v2s=%d, v3=%d\n",  
                timestamp(), host, port, result, v1_ok, v2_ok, v2s_ok, v3_ok);  
    } 
      
    // 检查历史记录  
    float uptime = -1.0f;  
    pthread_mutex_lock(&g_state.lock);  
    for (int i = 0; i < g_state.host_count; i++) {  
        if (strcmp(g_state.hosts[i].host, host) == 0 &&   
            g_state.hosts[i].port == port) {  
            uptime = calculate_uptime(&g_state.hosts[i]);
            if (verbose) {  
                fprintf(stderr, "[%s] [DEBUG]: API请求 %s:%d 找到历史记录: uptime=%.2f%%\n", timestamp(), host, port, uptime);  
            }  
            break;  
        }  
    }  
    pthread_mutex_unlock(&g_state.lock);  
      
    // 生成 SVG 响应  
    generate_svg_response(client_sock, result == 0, uptime, v1_ok, v2_ok, v2s_ok, v3_ok);  
}
// HTTP 请求处理
void handle_http_request(int client_sock)  
{  
    if (verbose)  
    {  
        fprintf(stderr, "[%s] [DEBUG]: 开始处理 HTTP 请求 (socket fd=%d)\n", timestamp(), client_sock);  
    }  
    char request[1024];  
    ssize_t n = recv(client_sock, request, sizeof(request) - 1, 0);  
    if (verbose)  
    {  
        fprintf(stderr, "[%s] [DEBUG]: 接收到 %zd 字节请求数据\n", timestamp(), n);  
    }  
      
    if (n > 0) {  
        request[n] = '\0';  
          
        // 解析请求行: GET /api?supernode=host:port HTTP/1.1    
        char method[16], path[512], version[16];    
        if (sscanf(request, "%15s %511s %15s", method, path, version) == 3) {  
            if (verbose) {  
                fprintf(stderr, "[%s] [DEBUG]: 解析请求: method=%s, path=%s, version=%s\n",  
                        timestamp(), method, path, version);  
            }  
              
            if (strncmp(path, "/api", 4) == 0) {  
                if (verbose) {  
                    fprintf(stderr, "[%s] [DEBUG]: 识别为 API 请求，转发到 handle_api_request()\n", timestamp());  
                }  
                handle_api_request(client_sock, path);    
                return;    
            }  
              
            if (verbose) {  
                fprintf(stderr, "[%s] [DEBUG]: 识别为主页请求，生成 HTML 响应\n", timestamp());  
            }  
        } else {  
            if (verbose) {  
                fprintf(stderr, "[%s] [DEBUG]: 请求行解析失败\n", timestamp());  
            }  
        }  
               
        char *response = malloc(262144);  // 256KB      
        if (response) {  
            if (verbose) {  
                fprintf(stderr, "[%s] [DEBUG]: 开始生成 HTML 内容\n", timestamp());  
            }  
              
            generate_html(response, 262144);      
            size_t response_len = strlen(response);    
            ssize_t sent = send(client_sock, response, response_len, 0);  
              
            if (verbose) {    
                fprintf(stderr, "[%s] [DEBUG]: 发送响应: %zd/%zu 字节\n", timestamp(), sent, response_len);    
            }      
            free(response);      
        } else {    
            if (verbose) {    
                fprintf(stderr, "[%s] [ERROR]: 响应缓冲区分配失败\n", timestamp());    
            }    
        }     
    } else if (n == 0) {    
        if (verbose) {    
            fprintf(stderr, "[%s] [DEBUG]: 客户端关闭连接\n", timestamp());    
        }    
    } else {    
        if (verbose) {    
            fprintf(stderr, "[%s] [ERROR]: recv() 错误: %s\n", timestamp(), strerror(errno));    
        }    
    }     
          
    close(client_sock);   
    if (verbose) {    
        fprintf(stderr, "[%s] [DEBUG]: HTTP 请求处理完成,连接已关闭\n", timestamp());    
    }     
}

// 监控线程
void *monitor_thread(void *arg)
{
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 监控线程启动\n", timestamp());
    }
    int round = 0;
    while (g_state.running)
    {
        round++;

		// 检查配置文件是否被修改  
        if (g_state.config_file_path[0] != '\0') {  
            struct stat st;  
            if (stat(g_state.config_file_path, &st) == 0) {  
                if (st.st_mtime > g_state.config_mtime) {  
                        fprintf(stderr, "[%s] [DEBUG]: 配置文件已修改 (旧时间=%ld, 新时间=%ld)重新加载\n",  
                                timestamp(), g_state.config_mtime, st.st_mtime);  
                    g_state.config_mtime = st.st_mtime;  
                    reload_config();  
                }  
            } else if (verbose) {  
                fprintf(stderr, "[%s] [WARN]: 无法访问配置文件: %s\n",  
                        timestamp(), strerror(errno));  
            }  
        }

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 开始第 %d 轮检测 (共 %d 个主机)\n",
                    timestamp(), round, g_state.host_count);
        }
        for (int i = 0; i < g_state.host_count; i++)
        {
            host_stats_t *h = &g_state.hosts[i];
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 检测主机 %d/%d: %s:%d\n",
                        timestamp(), i + 1, g_state.host_count, h->host, h->port);
            }

            int v1_ok = 0, v2_ok = 0, v2s_ok = 0, v3_ok = 0;
            int result = test_supernode_internal(h->host, h->port, &v1_ok, &v2_ok, &v2s_ok, &v3_ok);

            pthread_mutex_lock(&g_state.lock);
            h->total_checks++;

            int before_v1 = h->success_v1;
            int before_v2 = h->success_v2;
            int before_v2s = h->success_v2s;
            int before_v3 = h->success_v3;

            if (v1_ok)
                h->success_v1++;
            if (v2_ok)
                h->success_v2++;
            if (v2s_ok)
                h->success_v2s++;
            if (v3_ok)
                h->success_v3++;
            h->last_check = time(NULL);

            // 【新增】判断本次检测是否在线(任一版本成功即为在线)
            int is_online = (v1_ok || v2_ok || v2s_ok || v3_ok);

            // 【新增】添加检测记录到历史数组
            add_check_record(h, is_online);

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 添加历史记录: %s (history_count=%d, history_index=%d)\n",
                        timestamp(), h->host, h->port,
                        is_online ? "在线" : "离线",
                        h->history_count, h->history_index);
            }

            if (is_online)
            {
                snprintf(h->last_status, sizeof(h->last_status), "✓ 在线");
            }
            else
            {
                snprintf(h->last_status, sizeof(h->last_status), "✗ 离线");
            }

            // 【新增】保存历史记录到文件
            save_history(h);

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 历史记录已保存到 %s/%s_%d.dat\n",
                        timestamp(), h->host, h->port, STATE_DIR, h->host, h->port);
            }

            pthread_mutex_unlock(&g_state.lock);

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测结果: %s (v1:%s v2:%s v2s:%s v3:%s)\n",
                        timestamp(), h->host, h->port,
                        result == 0 ? "成功" : "失败",
                        v1_ok ? "✓" : "✗",
                        v2_ok ? "✓" : "✗",
                        v2s_ok ? "✓" : "✗",
                        v3_ok ? "✓" : "✗");
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 累计统计: 总检测=%d, v1=%d, v2=%d, v2s=%d, v3=%d\n",
                        timestamp(), h->host, h->port,
                        h->total_checks, h->success_v1, h->success_v2, h->success_v2s, h->success_v3);

                // 【新增】输出连通率信息
                float uptime = calculate_uptime(h);
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 连通率: %.2f%% (基于最近 %d 次检测)\n",
                        timestamp(), h->host, h->port, uptime, h->history_count);
            }
        }
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 第 %d 轮检测完成,等待 %d 分钟后开始下一轮\n",
                    timestamp(), round, g_state.check_interval_minutes);
        }
        sleep(g_state.check_interval_minutes * 60);
    }
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 监控线程退出\n", timestamp());
    }
    return NULL;
}

static int init_http_server(int port)
{
    int http_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (http_sock < 0)
    {
        fprintf(stderr, "[%s] [ERROR]: HTTP socket 创建失败: %s\n", timestamp(), strerror(errno));
        return -1;
    }

    int opt = 1;
    if (setsockopt(http_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [WARN]: 设置端口复用失败: %s\n", timestamp(), strerror(errno));
        }
    }
    else if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 端口复用设置成功\n", timestamp());
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 绑定地址 0.0.0.0:%d\n", timestamp(), port);
    }
    if (bind(http_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        fprintf(stderr, "[%s] [ERROR]: HTTP bind 失败: %s\n", timestamp(), strerror(errno));
        close(http_sock);
        return -1;
    }

    if (listen(http_sock, 5) < 0)
    {
        fprintf(stderr, "[%s] [ERROR]: HTTP listen 失败: %s\n", timestamp(), strerror(errno));
        close(http_sock);
        return -1;
    }
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: listen() 成功 (backlog=5)\n", timestamp());
        fprintf(stderr, "[%s] [DEBUG]: HTTP 服务器初始化完成\n", timestamp());
    }
    return http_sock;
}

// 打印帮助信息
static void print_help(const char *prog_name)
{
    printf("N2N supernode 检测工具\n\n");
    printf("用法: %s [选项] <主机1:端口1> [主机2:端口2] ...\n\n", prog_name);
    printf("选项:\n");
    printf("  -p <端口>       服务主页监听端口 (默认: 8585)\n");
    printf("  -i <分钟>       指定探测间隔时间（分钟）(默认: 1)\n");
    printf("  -f <文件>       从配置文件读取主机列表(支持备注)\n");
    printf("  -c <社区名>     指定探测使用的社区名称 (默认: N2N_check_bot)\n");
    printf("  -m <MAC地址>    指定探测使用的MAC地址,格式: a1:b2:c3:d4:f5:g6 (默认: a1:b2:c3:d4:f5:06)\n");
    printf("  -4              仅使用 IPv4 (默认)\n");
    printf("  -6              同时支持 IPv4 和 IPv6\n\n");
    printf("  -v              详细模式（显示调试信息）\n");
    printf("  -h              显示此帮助信息\n");
    printf("配置文件格式:\n");
    printf("  host:port|备注\n");
    printf("  例如: n2n.example.com:10086|北京电信\n\n");
    printf("命令示例:\n");
    printf("  %s -p 8080 -i 2 n2n.example.com:10086 192.168.1.1:10090\n", prog_name);
    printf("  %s -v -6 \"supernode.example.com:7777|北京电信\" \"192.168.1.1:10090|自建\"\n", prog_name);
    printf("  %s -p 8080 -i 2 -f n2n_host.conf\n", prog_name);
    printf("\n");
}

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    srand(time(NULL));

    int http_port = 8585;
    int check_interval = 1;
    char *config_file = NULL;
    int arg_start = 1;
    int use_ipv6 = 0; // 默认仅 IPv4

    // 解析命令行参数
    while (arg_start < argc)
    {
        if (strcmp(argv[arg_start], "-h") == 0 || strcmp(argv[arg_start], "--help") == 0)
        {
            print_help(argv[0]);
            return 0;
        }
        else if (strcmp(argv[arg_start], "-v") == 0)
        {
            verbose = 1;
            arg_start++;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 详细模式已启用\n", timestamp());
            }
        }
        else if (strcmp(argv[arg_start], "-p") == 0 && arg_start + 1 < argc)
        {
            http_port = atoi(argv[arg_start + 1]);
            if (http_port <= 0 || http_port > 65535)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的 HTTP 端口号 %d\n", timestamp(), http_port);
                return 1;
            }
            arg_start += 2;
        }
        else if (strcmp(argv[arg_start], "-i") == 0 && arg_start + 1 < argc)
        {
            check_interval = atoi(argv[arg_start + 1]);
            if (check_interval <= 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的检测间隔 %d\n", timestamp(), check_interval);
                return 1;
            }
            arg_start += 2;
        }
        else if (strcmp(argv[arg_start], "-f") == 0 && arg_start + 1 < argc)
        {
            config_file = argv[arg_start + 1];
			strncpy(g_state.config_file_path, config_file, sizeof(g_state.config_file_path) - 1);
            arg_start += 2;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 使用配置文件: %s\n", timestamp(), config_file);
            }
        }
        else if (strcmp(argv[arg_start], "-c") == 0 && arg_start + 1 < argc)
        {
            strncpy(g_community, argv[arg_start + 1], N2N_COMMUNITY_SIZE - 1);
            g_community[N2N_COMMUNITY_SIZE - 1] = '\0';
            arg_start += 2;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 使用社区名: %s\n", timestamp(), g_community);
            }
        }
        else if (strcmp(argv[arg_start], "-m") == 0 && arg_start + 1 < argc)
        {
            if (parse_mac(argv[arg_start + 1], g_mac) < 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的 MAC 地址格式: %s\n", timestamp(), argv[arg_start + 1]);
                fprintf(stderr, "正确格式如: a1:b2:c3:d4:f5:g6\n");
                return 1;
            }
            arg_start += 2;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 使用 MAC 地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        timestamp(), g_mac[0], g_mac[1], g_mac[2], g_mac[3], g_mac[4], g_mac[5]);
            }
        }
        else if (strcmp(argv[arg_start], "-4") == 0)
        {
            use_ipv6 = 0;
            arg_start++;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 仅使用 IPv4\n", timestamp());
            }
        }
        else if (strcmp(argv[arg_start], "-6") == 0)
        {
            use_ipv6 = 1;
            arg_start++;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 启用 IPv4 和 IPv6 支持\n", timestamp());
            }
        }
        else
        {
            break;
        }
    }

    // 初始化状态
    pthread_mutex_init(&g_state.lock, NULL);
    g_state.check_interval_minutes = check_interval;
    g_state.start_time = time(NULL);
    g_state.running = 1;

    // 创建状态目录
    struct stat st = {0};
    if (stat(STATE_DIR, &st) == -1)
    {
        if (mkdir(STATE_DIR, 0755) == -1)
        {
            fprintf(stderr, "[%s] [ERROR]: 无法创建状态目录 %s: %s\n",
                    timestamp(), STATE_DIR, strerror(errno));
            fprintf(stderr, "[%s] [WARN]: 历史记录功能将不可用\n", timestamp());
        }
        else
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 已创建状态目录: %s\n", timestamp(), STATE_DIR);
            }
        }
    }
    // 读取配置文件
    if (config_file)
    {
        load_config(config_file);
		// 记录初始修改时间  
    	struct stat st;  
    	if (stat(config_file, &st) == 0) {  
        	g_state.config_mtime = st.st_mtime;  
    	}	
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 初始化全局状态，检测间隔时间 %d 分钟\n", timestamp(), check_interval);
    }

    // 解析主机列表
    for (int i = arg_start; i < argc && g_state.host_count < MAX_HOSTS; i++)
    {
        char *host_str = strdup(argv[i]);
        if (!host_str)
        {
            fprintf(stderr, "[%s] [ERROR]: 内存分配失败\n", timestamp());
            continue;
        }

        char host[256] = {0};
        int port = 10086;
        char note[512] = {0};

        // 解析备注 (格式: host:port|备注)
        char *pipe = strchr(host_str, '|');
        if (pipe)
        {
            *pipe = '\0';
            strncpy(note, pipe + 1, sizeof(note) - 1);
        }
        // 解析端口
        char *port_str = strchr(host_str, ':');
        if (port_str)
        {
            *port_str = '\0';
            port = atoi(port_str + 1);
            if (port <= 0 || port > 65535)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的端口号 %d (主机: %s)\n", timestamp(), port, host_str);
                free(host_str);
                continue;
            }
        }

        strncpy(host, host_str, sizeof(host) - 1);

        host_stats_t *h = &g_state.hosts[g_state.host_count];
        strncpy(h->host, host_str, sizeof(h->host) - 1);
        h->port = port;
        strncpy(h->note, note, sizeof(h->note) - 1);
        load_history(h);
        g_state.host_count++;

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 检测主机 ==> %s:%d", timestamp(), host, port);
            if (note[0])
            {
                fprintf(stderr, " (备注: %s)", note);
            }
            fprintf(stderr, "\n");
        }

        free(host_str);
    }

    if (g_state.host_count == 0)
    {
        fprintf(stderr, "[%s] [ERROR]: 没有有效的主机需要检测\n", timestamp());
        return 1;
    }

    printf("[%s] [INFO]: 共计检测 %d 个主机\n", timestamp(), g_state.host_count);

    // 初始化 HTTP 服务器 (支持 IPv4/IPv6)
    int http_sock = -1;

    if (use_ipv6)
    {
        // 尝试创建 IPv6 socket (同时支持 IPv4)
        http_sock = socket(AF_INET6, SOCK_STREAM, 0);
        if (http_sock >= 0)
        {
            int opt = 1;
            setsockopt(http_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            // 允许 IPv6 socket 同时接受 IPv4 连接
            int ipv6only = 0;
            if (setsockopt(http_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) < 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 无法设置 IPV6_V6ONLY=0: %s\n", timestamp(), strerror(errno));
                }
            }

            struct sockaddr_in6 addr6 = {0};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_addr = in6addr_any;
            addr6.sin6_port = htons(http_port);

            if (bind(http_sock, (struct sockaddr *)&addr6, sizeof(addr6)) < 0)
            {
                fprintf(stderr, "[%s] [WARN]: IPv6 bind 失败: %s, 回退到 IPv4\n", timestamp(), strerror(errno));
                close(http_sock);
                http_sock = -1;
            }
            else
            {
                if (listen(http_sock, 5) < 0)
                {
                    fprintf(stderr, "[%s] [WARN]: IPv6 listen 失败: %s, 回退到 IPv4\n", timestamp(), strerror(errno));
                    close(http_sock);
                    http_sock = -1;
                }
                else
                {
                    if (verbose)
                    {
                        fprintf(stderr, "[%s] [DEBUG]: 服务主页将同时监听 IPv6 IPv4\n", timestamp());
                    }
                }
            }
        }
        else
        {
            fprintf(stderr, "[%s] [WARN]: 无法创建 IPv6 socket: %s, 回退到 IPv4\n", timestamp(), strerror(errno));
        }
    }

    // 如果 IPv6 失败或未启用,使用 IPv4
    if (http_sock < 0)
    {
        http_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (http_sock < 0)
        {
            fprintf(stderr, "[%s] [ERROR]: HTTP socket 创建失败", timestamp());
            return 1;
        }

        int opt = 1;
        setsockopt(http_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(http_port);

        if (bind(http_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            fprintf(stderr, "[%s] [ERROR]: HTTP bind 失败", timestamp());
            close(http_sock);
            return 1;
        }

        if (listen(http_sock, 5) < 0)
        {
            fprintf(stderr, "[%s] [ERROR]: HTTP listen 失败", timestamp());
            close(http_sock);
            return 1;
        }
    }

    // 启动监控线程
    pthread_t monitor_tid;
    if (pthread_create(&monitor_tid, NULL, monitor_thread, NULL) != 0)
    {
        fprintf(stderr, "[%s] [ERROR]: 检测线程创建失败", timestamp());
        close(http_sock);
        return 1;
    }

    printf("[%s] [INFO]: 服务已启动,主页地址: http://localhost:%d \n", timestamp(), http_port);
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG] 探测使用的社区名: %s, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                timestamp(), g_community, g_mac[0], g_mac[1], g_mac[2], g_mac[3], g_mac[4], g_mac[5]);
    }
    // 主循环处理 HTTP 请求
    while (1)
    {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(http_sock, (struct sockaddr *)&client_addr, &client_len);

        if (client_sock >= 0)
        {
            // if (verbose)
            // {
                char client_ip[INET6_ADDRSTRLEN];
                if (client_addr.ss_family == AF_INET)
                {
                    inet_ntop(AF_INET, &((struct sockaddr_in *)&client_addr)->sin_addr,
                              client_ip, sizeof(client_ip));
                    fprintf(stderr, "[%s] [DEBUG]: 来自 [%s] 访问\n", timestamp(), client_ip);
                }
                else if (client_addr.ss_family == AF_INET6)
                {
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&client_addr)->sin6_addr,
                              client_ip, sizeof(client_ip));
                    fprintf(stderr, "[%s] [DEBUG]: 来自 [%s] 访问\n", timestamp(), client_ip);
                }
            // }
            handle_http_request(client_sock);
        }
        else if (errno != EINTR)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [ERROR]: accept() 错误: %s\n", timestamp(), strerror(errno));
            }
        }
    }

    return 0;
}
