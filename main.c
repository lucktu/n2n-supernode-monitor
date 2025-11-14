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
#include <syslog.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <signal.h>
#include <ctype.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zlib.h>

#define N2N_COMMUNITY_SIZE 20
#define N2N_MAC_SIZE 6
#define N2N_COOKIE_SIZE 4
#define N2N_DESC_SIZE 16
#define MSG_TYPE_REGISTER_SUPER 5
#define COMMUNITY_LEN 16
#define MSG_TYPE_REGISTER 1
#define MSG_TYPE_REGISTER_ACK 4
#define MAX_HOSTS 100

static int g_enable_syslog = 0;                     // 输出日志到系统日志
static int g_syslog_pipe[2];                        // 管道文件描述符
static pthread_t g_syslog_thread;                   // syslog 转发线程
static int g_syslog_running = 0;                    // 线程运行标志
time_t last_manual_refresh = 0;                     // 记录上次手动刷新时间
int manual_refresh_interval = 5;                    // 默认1分钟检测间隔
static long g_timeout_ms = 1000;                    // 默认 1000ms (1秒)未响应判定为离线
static int g_max_retries = 5;                       // 默认5次 检测重试次数
static int g_max_history = 300;                     // 默认300条 保存的最大历史检测记录
static char g_state_dir[1024] = "/tmp/n2n_monitor"; // 默认历史检测记录保存路径
static char g_callback_script[1024] = "";           // 回调脚本路径
static int g_max_parallel_checks = 5;               // 默认 5 个并行线程进行检测
static char *g_html_cache = NULL;                   // HTML 缓存
static size_t g_html_cache_size = 0;                // 缓存大小
static pthread_rwlock_t g_cache_lock;               // 缓存读写锁

static int verbose = 0;
static char g_community[N2N_COMMUNITY_SIZE] = "N2N_check_bot";
static uint8_t g_mac[N2N_MAC_SIZE] = {0xa1, 0xb2, 0xc3, 0xd4, 0xf5, 0x06}; // a1:b2:c3:d4:f5:06
static volatile sig_atomic_t g_shutdown_requested = 0;

// 并行检测任务结构
typedef struct
{
    char host[256]; // 要检测的主机
    int port;       // 端口
    int host_index; // 在 g_state.hosts 中的索引
    int v1_ok;      // v1 检测结果
    int v2_ok;      // v2 检测结果
    int v2s_ok;     // v2s 检测结果
    int v3_ok;      // v3 检测结果
    int is_online;  // 是否在线
} check_task_t;

// 单次检测记录
typedef struct
{
    time_t timestamp;
    int success; // 0=离线, 1=在线
} check_record_t;

// 统计数据结构
typedef struct
{
    char host[256]; // 实际主机名/IP
    int port;
    char note[2048];        // 备注
    char display_name[256]; // 前端显示主机名
    int total_checks;
    int success_v1;
    int success_v2;
    int success_v2s;
    int success_v3;
    time_t last_check;
    char last_status[64];
    check_record_t *history; // 循环历史记录
    int history_index;       // 当前写入位置
    int history_count;       // 已有记录数
    int max_history;         // 记录该主机的最大历史数
    int last_online_status;  // 0=离线, 1=在线, -1=未初始化
} host_stats_t;

typedef struct
{
    host_stats_t hosts[MAX_HOSTS];
    int host_count;
    pthread_rwlock_t lock;
    int check_interval_minutes;
    time_t start_time;
    int running;
    char config_file_path[1024]; // :配置文件路径
    time_t config_mtime;         // 配置文件最后修改时间
} uptime_state_t;

static uptime_state_t g_state = {0};

// syslog 转发线程
void *syslog_forwarder_thread(void *arg)
{
    (void)arg;
    char buffer[4096];
    char line_buffer[8192] = {0}; // 行缓冲区
    size_t line_len = 0;          // 当前行长度
    ssize_t n;
    int original_stderr = *(int *)arg; // 接收原始 stderr

    openlog("【N2N-monitor】", LOG_PID | LOG_CONS, LOG_DAEMON);

    if (verbose)
    {
        syslog(LOG_INFO, "syslog 日志输出已启动");
    }

    while (g_syslog_running && (n = read(g_syslog_pipe[0], buffer, sizeof(buffer) - 1)) > 0)
    {
        // 逐字符处理,查找换行符
        for (ssize_t i = 0; i < n; i++)
        {
            if (buffer[i] == '\n')
            {
                // 遇到换行符,输出完整的行
                line_buffer[line_len] = '\0';

                // 解析日志级别
                int priority = LOG_INFO;
                if (strstr(line_buffer, "[ERROR]"))
                {
                    priority = LOG_ERR;
                }
                else if (strstr(line_buffer, "[WARN]"))
                {
                    priority = LOG_WARNING;
                }
                else if (strstr(line_buffer, "[DEBUG]"))
                {
                    priority = LOG_DEBUG;
                }

                // 写入 syslog
                syslog(priority, "%s", line_buffer);

                // 同时输出到原始控制台(包含换行符)
                if (original_stderr >= 0)
                {
                    ssize_t written = write(original_stderr, line_buffer, line_len);
                    if (written < 0)
                    {
                        int err = errno;
                        if (err == EBADF || err == EPIPE)
                        {
                            // 致命错误,停止写入控制台
                            if (verbose)
                            {
                                syslog(LOG_WARNING, "控制台输出已禁用: %s", strerror(err));
                            }
                            close(original_stderr);
                            original_stderr = -1;
                        }
                        else if (verbose && err != EINTR)
                        {
                            // 非中断错误才记录
                            syslog(LOG_WARNING, "日志同步输出到控制台失败: %s", strerror(err));
                        }
                    }
                    else
                    {
                        // 成功写入行内容,添加换行符
                        if (write(original_stderr, "\n", 1) < 0 && verbose && errno != EINTR)
                        {
                            syslog(LOG_WARNING, "写入换行符失败: %s", strerror(errno));
                        }
                    }
                }

                // 重置行缓冲区
                line_len = 0;
            }
            else
            {
                // 累积字符到行缓冲区
                if (line_len < sizeof(line_buffer) - 1)
                {
                    line_buffer[line_len++] = buffer[i];
                }
                else if (verbose)
                {
                    // 行太长,记录警告(只记录一次)
                    static int overflow_warned = 0;
                    if (!overflow_warned)
                    {
                        syslog(LOG_WARNING, "日志行超过缓冲区大小,已截断");
                        overflow_warned = 1;
                    }
                }
            }
        }
    }

    // 处理最后可能未完成的行
    if (line_len > 0)
    {
        line_buffer[line_len] = '\0';
        syslog(LOG_INFO, "%s", line_buffer);
        if (original_stderr >= 0)
        {
            if (write(original_stderr, line_buffer, line_len) >= 0)
            {
                if (write(original_stderr, "\n", 1) < 0 && verbose && errno != EINTR)
                {
                    syslog(LOG_WARNING, "写入换行符失败: %s", strerror(errno));
                }
            }
        }
    }

    closelog();
    if (original_stderr >= 0)
    {
        close(original_stderr);
    }
    return NULL;
}

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

// 去掉字符串末尾的空白字符（空格、制表符、换行符、回车）
void trim_right(char *str)
{
    if (!str)
        return;
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1]))
    {
        str[len - 1] = '\0';
        len--;
    }
}

// 解析MAC地址字符串 (格式: a1:b2:c3:d4:f5:06)
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
    const int MAX_RETRIES = g_max_retries;
    int retry_attempt = 0;

    *v1_ok = *v2_ok = *v2s_ok = *v3_ok = 0;

    // 重试循环
    while (retry_attempt < MAX_RETRIES)
    {
        if (verbose && retry_attempt > 0)
        {
            fprintf(stderr, "[%s] [DEBUG]: %s:%d 第 %d 次重试\n",
                    timestamp(), host, port, retry_attempt);
        }

        // DNS 解析
        struct sockaddr_in addr;
        struct addrinfo hints = {0};
        struct addrinfo *result = NULL;

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

        // 构建数据包
        uint8_t pktbuf_v1[2048], pktbuf_v2[2048], pktbuf_v2s[2048], pktbuf_v3[2048];
        uint8_t recvbuf[2048];

        uint8_t cookie_v2[N2N_COOKIE_SIZE] = {0xA2, 0xB2, 0xC2, 0xD2};
        uint8_t cookie_v2s[N2N_COOKIE_SIZE] = {0x11, 0x22, 0x33, 0x44};
        uint8_t cookie_v3[N2N_COOKIE_SIZE] = {0xA3, 0xB3, 0xC3, 0xD3};

        char community[N2N_COMMUNITY_SIZE];
        strncpy(community, g_community, N2N_COMMUNITY_SIZE - 1);
        community[N2N_COMMUNITY_SIZE - 1] = '\0';

        size_t pkt_len_v1 = build_register_v1(pktbuf_v1, community);
        size_t pkt_len_v2 = build_register_super_v2(pktbuf_v2, community, cookie_v2);
        size_t pkt_len_v2s = build_register_super_v2s(pktbuf_v2s, community, cookie_v2s);
        size_t pkt_len_v3 = build_register_super_v3(pktbuf_v3, community, cookie_v3);

        // 创建 socket
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            fprintf(stderr, "[%s] [ERROR]: %s:%d - Socket 创建失败: %s\n", timestamp(), host, port, strerror(errno));
            return -1;
        }

        // 设置非阻塞模式
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        // 发送所有数据包
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

        // 接收响应
        struct timeval start_tv, now_tv;
        gettimeofday(&start_tv, NULL);
        long timeout_ms = g_timeout_ms;
        int responses_received = 0;
        int consecutive_empty = 0;
        long last_log_ms = 0;

        while (1)
        {
            gettimeofday(&now_tv, NULL);
            long elapsed_ms = (now_tv.tv_sec - start_tv.tv_sec) * 1000 +
                              (now_tv.tv_usec - start_tv.tv_usec) / 1000;

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
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 达到超时时间 %ldms 未收到响应,停止等待\n", timestamp(), host, port, timeout_ms);
                }
                break;
            }

            if (*v1_ok && *v2_ok && *v2s_ok && *v3_ok)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 所有版本响应已收到,提前退出\n", timestamp(), host, port);
                }
                break;
            }

            ssize_t recv_len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);

            if (recv_len < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    consecutive_empty++;
                    if (consecutive_empty >= 5 && responses_received > 0)
                    {
                        if (verbose)
                        {
                            fprintf(stderr, "[%s] [DEBUG]: %s:%d 连续 %d 次无数据,提前退出\n",
                                    timestamp(), host, port, consecutive_empty);
                        }
                        break;
                    }
                    usleep(20000);
                    continue;
                }
                else
                {
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

            // 验证各版本响应
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
            }
        }

        close(sock);

        // 检查是否有任何版本成功
        if (*v1_ok || *v2_ok || *v2s_ok || *v3_ok)
        {
            // 至少有一个版本成功，立即返回成功
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测成功（第 %d 次尝试）- v1:%s v2:%s v2s:%s v3:%s\n",
                        timestamp(), host, port, retry_attempt + 1,
                        *v1_ok ? "✓" : "✗",
                        *v2_ok ? "✓" : "✗",
                        *v2s_ok ? "✓" : "✗",
                        *v3_ok ? "✓" : "✗");
            }
            return 0;
        }

        // 所有版本都失败
        retry_attempt++;

        if (retry_attempt < MAX_RETRIES)
        {
            // 还有重试机会，等待 500ms 后重试
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测失败，等待 500ms 后重试（剩余 %d 次机会）\n",
                        timestamp(), host, port, MAX_RETRIES - retry_attempt);
            }
            usleep(500000); // 等待 500ms
        }
    }

    // 所有重试都失败
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测完成（已重试 %d 次）- v1:%s v2:%s v2s:%s v3:%s\n",
                timestamp(), host, port, MAX_RETRIES,
                *v1_ok ? "✓" : "✗",
                *v2_ok ? "✓" : "✗",
                *v2s_ok ? "✓" : "✗",
                *v3_ok ? "✓" : "✗");
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 未收到任何响应,主机不可达?端口关闭?被过滤?\n",
                timestamp(), host, port);
    }

    return -1;
}

// 加载历史记录
static void load_history(host_stats_t *host)
{
    // 【修复】创建安全的文件名(替换特殊字符)
    char safe_host[512];
    strncpy(safe_host, host->host, sizeof(safe_host) - 1);
    safe_host[sizeof(safe_host) - 1] = '\0';

    // 将 / 和 : 替换为 .
    for (char *p = safe_host; *p; p++)
    {
        if (*p == '/' || *p == ':')
        {
            *p = '.';
        }
    }

    char filename[2048];
    snprintf(filename, sizeof(filename), "%s/%s_%d.dat", g_state_dir, safe_host, host->port);

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

    // 【修复】添加边界检查
    size_t read_count;

    read_count = fread(&host->history_index, sizeof(int), 1, f);
    if (read_count != 1)
        goto read_error;

    read_count = fread(&host->history_count, sizeof(int), 1, f);
    if (read_count != 1)
        goto read_error;

    // 验证数据完整性
    if (host->history_index < 0 || host->history_index >= host->max_history ||
        host->history_count < 0 || host->history_count > host->max_history)
    {
        fprintf(stderr, "[%s] [ERROR]: %s:%d 历史记录数据损坏\n",
                timestamp(), host->host, host->port);
        fclose(f);
        return;
    }

    read_count = fread(host->history, sizeof(check_record_t), host->max_history, f);
    if ((int)read_count != host->max_history)
        goto read_error;

    read_count = fread(&host->total_checks, sizeof(int), 1, f);
    if (read_count != 1)
        goto read_error;

    read_count = fread(&host->success_v1, sizeof(int), 1, f);
    if (read_count != 1)
        goto read_error;

    read_count = fread(&host->success_v2, sizeof(int), 1, f);
    if (read_count != 1)
        goto read_error;

    read_count = fread(&host->success_v2s, sizeof(int), 1, f);
    if (read_count != 1)
        goto read_error;

    read_count = fread(&host->success_v3, sizeof(int), 1, f);
    if (read_count != 1)
        goto read_error;

    fclose(f);
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 已加载历史记录: history_count=%d, total_checks=%d\n",
                timestamp(), host->host, host->port, host->history_count, host->total_checks);
        fprintf(stderr, "[%s] [DEBUG]: %s:%d 累计成功: v1=%d, v2=%d, v2s=%d, v3=%d\n",
                timestamp(), host->host, host->port,
                host->success_v1, host->success_v2, host->success_v2s, host->success_v3);
    }
    return;

read_error:
    fprintf(stderr, "[%s] [ERROR]: %s:%d 读取历史记录文件失败\n",
            timestamp(), host->host, host->port);
    fclose(f);
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

    host->history_index = (host->history_index + 1) % host->max_history;
    if (host->history_count < host->max_history)
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

        // 去除行首空格
        char *trimmed_line = line;
        while (*trimmed_line == ' ' || *trimmed_line == '\t')
        {
            trimmed_line++;
        }

        // 跳过注释和空行 - 使用 trimmed_line
        if (trimmed_line[0] == '#' || trimmed_line[0] == '\n')
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
        char display_name[256] = {0};

        // 格式: host:port|备注|前端显示主机名
        char *first_pipe = strchr(trimmed_line, '|');
        if (first_pipe)
        {
            *first_pipe = '\0';
            char *second_pipe = strchr(first_pipe + 1, '|');
            if (second_pipe)
            {
                *second_pipe = '\0';
                strncpy(note, first_pipe + 1, sizeof(note) - 1);
                strncpy(display_name, second_pipe + 1, sizeof(display_name) - 1);
                char *newline = strchr(display_name, '\n');
                if (newline)
                    *newline = '\0';
            }
            else
            {
                strncpy(note, first_pipe + 1, sizeof(note) - 1);
                char *newline = strchr(note, '\n');
                if (newline)
                    *newline = '\0';
            }
        }

        // 解析端口 - 支持特殊前缀
        char *colon = NULL;
        int has_special_prefix = 0;

        // 先检查特殊前缀(在修改字符串之前)
        if (strncmp(trimmed_line, "txt:", 4) == 0)
        {
            has_special_prefix = 1;
            // 跳过 txt: 前缀后再查找端口
            colon = strchr(trimmed_line + 4, ':');
        }
        else if (strncmp(trimmed_line, "http:", 5) == 0)
        {
            has_special_prefix = 1;
            // 对于 http: 前缀,需要先查找路径分隔符
            const char *host_part = trimmed_line + 5;
            char *slash = strchr(host_part, '/');

            if (slash)
            {
                // 有路径,不提取端口,保持完整主机名
                colon = NULL;
                port = 0; // 端口设为 0
            }
            else
            {
                // 没有路径,正常查找端口
                colon = strchr(host_part, ':');
            }
        }
        else
        {
            // 普通主机
            colon = strchr(trimmed_line, ':');
        }

        if (colon)
        {
            // 对于 http: 前缀,需要检查冒号后是否有斜杠
            if (has_special_prefix && strncmp(trimmed_line, "http:", 5) == 0)
            {
                char *slash_after_colon = strchr(colon + 1, '/');
                if (slash_after_colon)
                {
                    // 提取端口(在斜杠之前)
                    char port_str[16];
                    size_t port_len = slash_after_colon - (colon + 1);
                    if (port_len < sizeof(port_str))
                    {
                        strncpy(port_str, colon + 1, port_len);
                        port_str[port_len] = '\0';
                        port = atoi(port_str);
                        // 不要修改 colon,保持完整的主机名
                        colon = NULL;
                    }
                }
                else
                {
                    *colon = '\0';
                    port = atoi(colon + 1);
                }
            }
            else
            {
                *colon = '\0';
                port = atoi(colon + 1);
            }

            // 特殊前缀允许端口为 0
            if (has_special_prefix)
            {
                if (port < 0 || port > 65535)
                {
                    fprintf(stderr, "[%s] [WARN]: 无效的端口号 %d (第 %d 行)\n",
                            timestamp(), port, line_num);
                    continue;
                }
            }
            else
            {
                // 普通主机端口必须有效
                if (port <= 0 || port > 65535)
                {
                    fprintf(stderr, "[%s] [WARN]: 无效的端口号 %d (第 %d 行)\n",
                            timestamp(), port, line_num);
                    continue;
                }
            }
        }
        else
        {
            // 没有端口号
            if (has_special_prefix)
            {
                // 特殊前缀允许无端口,自动填充为 0
                port = 0;
            }
        }

        // 复制主机名
        strncpy(host, trimmed_line, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0'; // 确保字符串结束

        // 去除末尾的换行符
        char *newline = strchr(host, '\n');
        if (newline)
        {
            *newline = '\0';
        }
        // 去除末尾的空格和制表符
        int len = strlen(host);
        while (len > 0 && (host[len - 1] == ' ' || host[len - 1] == '\t'))
        {
            host[--len] = '\0';
        }
        // 【新增】去除所有空白字符（空格、制表符、换行符、回车符）
        char cleaned_host[256] = {0};
        int j = 0;
        for (int i = 0; host[i] != '\0' && (size_t)j < sizeof(cleaned_host) - 1; i++)
        {
            if (host[i] != ' ' && host[i] != '\t' && host[i] != '\n' && host[i] != '\r')
            {
                cleaned_host[j++] = host[i];
            }
        }
        cleaned_host[j] = '\0';
        strncpy(host, cleaned_host, sizeof(host) - 1);

        // 检查是否重复
        int is_duplicate = 0;
        for (int j = 0; j < g_state.host_count; j++)
        {
            if (strcmp(g_state.hosts[j].host, host) == 0 &&
                g_state.hosts[j].port == port)
            {
                is_duplicate = 1;
                fprintf(stderr, "[%s] [WARN]: 忽略重复的主机 (第 %d 行): %s:%d\n",
                        timestamp(), line_num, host, port);
                break;
            }
        }

        if (is_duplicate)
        {
            continue;
        }

        host_stats_t *h = &g_state.hosts[g_state.host_count];
        strncpy(h->host, host, sizeof(h->host) - 1);
        h->port = port;
        strncpy(h->note, note, sizeof(h->note) - 1);
        strncpy(h->display_name, display_name, sizeof(h->display_name) - 1);
        h->last_online_status = -1;

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 第 %d 行解析成功: host=%s, port=%d, note=%s, display_name=%s\n",
                    timestamp(), line_num, host, port,
                    note[0] ? note : "(无)",
                    display_name[0] ? display_name : "(无)");
        }
        // 初始化 max_history 并分配内存
        h->max_history = g_max_history;
        h->history = calloc(g_max_history, sizeof(check_record_t));
        if (!h->history)
        {
            fprintf(stderr, "[%s] [ERROR]: 无法为 %s:%d 分配历史记录内存，跳过这个主机\n",
                    timestamp(), host, port);
            continue; // 跳过这个主机
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

static void save_history(const host_stats_t *host)
{
    // 确保目录存在
    struct stat st = {0};
    if (stat(g_state_dir, &st) == -1)
    {
        if (mkdir(g_state_dir, 0755) == -1)
        {
            fprintf(stderr, "[%s] [ERROR]: 无法创建目录 %s: %s\n", timestamp(), g_state_dir, strerror(errno));
            return;
        }
    }

    // 创建安全的文件名(替换特殊字符)
    char safe_host[512];
    strncpy(safe_host, host->host, sizeof(safe_host) - 1);
    safe_host[sizeof(safe_host) - 1] = '\0';

    // 将 / 和 : 替换为 .
    for (char *p = safe_host; *p; p++)
    {
        if (*p == '/' || *p == ':')
        {
            *p = '.';
        }
    }

    char filename[2048];
    snprintf(filename, sizeof(filename), "%s/%s_%d.dat", g_state_dir, safe_host, host->port);

    FILE *f = fopen(filename, "wb");
    if (!f)
    {
        fprintf(stderr, "[%s] [ERROR]: 无法写入检测记录文件 %s: %s\n", timestamp(), filename, strerror(errno));
        return;
    }

    fwrite(&host->history_index, sizeof(int), 1, f);
    fwrite(&host->history_count, sizeof(int), 1, f);
    fwrite(host->history, sizeof(check_record_t), host->max_history, f);
    fwrite(&host->total_checks, sizeof(int), 1, f);
    fwrite(&host->success_v1, sizeof(int), 1, f);
    fwrite(&host->success_v2, sizeof(int), 1, f);
    fwrite(&host->success_v2s, sizeof(int), 1, f);
    fwrite(&host->success_v3, sizeof(int), 1, f);

    fclose(f);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 已保存 %s:%d 的历史记录到 %s (共 %d 条)\n",
                timestamp(), host->host, host->port, filename, host->history_count);
    }
}

// 重新加载配置文件
static void reload_config(void)
{
    if (g_state.config_file_path[0] == '\0')
    {
        return; // 没有配置文件
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 检测到配置文件变化,开始重新加载\n", timestamp());
    }

    pthread_rwlock_wrlock(&g_state.lock);
    // 保存所有主机的历史记录
    for (int i = 0; i < g_state.host_count; i++)
    {
        save_history(&g_state.hosts[i]);
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 配置重载前已保存 %s:%d 的历史检测记录\n",
                    timestamp(), g_state.hosts[i].host, g_state.hosts[i].port);
        }
    }

    // 保存旧的主机数量
    int old_count = g_state.host_count;

    // 清空现有配置
    g_state.host_count = 0;
    memset(g_state.hosts, 0, sizeof(g_state.hosts));

    pthread_rwlock_unlock(&g_state.lock);

    // 重新加载配置文件
    load_config(g_state.config_file_path);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 配置重载完成: 旧主机数=%d, 新主机数=%d\n",
                timestamp(), old_count, g_state.host_count);
    }
}

#define DNS_TYPE_TXT 16
#define DNS_CLASS_IN 1

// 将域名转换为 DNS 查询格式
static int domain_to_qname(const char *domain, uint8_t *buf)
{
    const char *pos = domain;
    uint8_t *label_len_pos = buf;
    uint8_t label_len = 0;
    int out_len = 1;
    *label_len_pos = 0;

    while (*pos)
    {
        if (*pos == '.')
        {
            *label_len_pos = label_len;
            label_len = 0;
            label_len_pos = buf + out_len;
            *label_len_pos = 0;
            out_len++;
            pos++;
            continue;
        }
        buf[out_len++] = (uint8_t)*pos;
        label_len++;
        pos++;
    }
    *label_len_pos = label_len;
    buf[out_len++] = 0;
    return out_len;
}

// 构造 DNS 查询包
static int build_dns_query(const char *domain, uint8_t *out_buf, int out_buf_size, uint16_t txid)
{
    if (out_buf_size < 12)
        return -1;
    memset(out_buf, 0, out_buf_size);

    // DNS 头部
    out_buf[0] = (uint8_t)(txid >> 8);
    out_buf[1] = (uint8_t)(txid & 0xFF);
    out_buf[2] = 0x01; // 标准查询
    out_buf[3] = 0x00;
    out_buf[4] = 0x00;
    out_buf[5] = 0x01; // 1 个问题
    out_buf[6] = 0x00;
    out_buf[7] = 0x00;
    out_buf[8] = 0x00;
    out_buf[9] = 0x00;
    out_buf[10] = 0x00;
    out_buf[11] = 0x00;

    int pos = 12;
    uint8_t qname[256];
    int qname_len = domain_to_qname(domain, qname);
    memcpy(out_buf + pos, qname, qname_len);
    pos += qname_len;

    // 查询类型和类
    out_buf[pos++] = 0x00;
    out_buf[pos++] = DNS_TYPE_TXT;
    out_buf[pos++] = 0x00;
    out_buf[pos++] = DNS_CLASS_IN;

    return pos;
}

// 跳过 DNS 名称字段
static int dns_skip_name(const uint8_t *buf, int buf_len, int offset)
{
    while (1)
    {
        if (offset >= buf_len)
            return -1;
        uint8_t len = buf[offset];
        if ((len & 0xC0) == 0xC0)
            return offset + 2; // 压缩指针
        if (len == 0)
            return offset + 1;
        offset += 1 + len;
    }
}

// 解析 TXT 记录数据
static int extract_txt_value(const uint8_t *rdata, int rdlen, char *txt_value, int txt_size)
{
    int p = 0;
    int total_len = 0;

    while (p < rdlen && total_len < txt_size - 1)
    {
        uint8_t seg_len = rdata[p++];
        if (p + seg_len > rdlen)
            break;

        int copy_len = (total_len + seg_len < txt_size - 1) ? seg_len : (txt_size - 1 - total_len);
        memcpy(txt_value + total_len, rdata + p, copy_len);
        total_len += copy_len;
        p += seg_len;
    }

    txt_value[total_len] = '\0';
    return total_len > 0 ? 0 : -1;
}

// 解析 DNS 响应
static int parse_dns_txt_response(const uint8_t *buf, int buf_len, uint16_t expected_txid, char *txt_value, int txt_size)
{
    if (buf_len < 12)
        return -1;

    uint16_t txid = (buf[0] << 8) | buf[1];
    uint16_t flags = (buf[2] << 8) | buf[3];
    uint16_t qdcount = (buf[4] << 8) | buf[5];
    uint16_t ancount = (buf[6] << 8) | buf[7];

    // 验证事务 ID 和响应标志
    if (txid != expected_txid || (flags & 0x8000) == 0)
        return -1;

    // 检查响应码
    int rcode = flags & 0x000F;
    if (rcode != 0)
    {
        if (verbose)
        {
            const char *rcode_str[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
            fprintf(stderr, "[%s] [DEBUG]: DNS 错误: %s\n",
                    timestamp(), rcode < 6 ? rcode_str[rcode] : "UNKNOWN");
        }
        return -1;
    }

    if (ancount == 0)
        return -1;

    // 跳过问题部分
    int offset = 12;
    for (int i = 0; i < qdcount; i++)
    {
        int no = dns_skip_name(buf, buf_len, offset);
        if (no < 0)
            return -1;
        offset = no + 4;
    }

    // 解析回答部分
    for (int i = 0; i < ancount; i++)
    {
        int no = dns_skip_name(buf, buf_len, offset);
        if (no < 0)
            break;
        offset = no;

        if (offset + 10 > buf_len)
            break;

        uint16_t atype = (buf[offset] << 8) | buf[offset + 1];
        uint16_t aclass = (buf[offset + 2] << 8) | buf[offset + 3];
        uint16_t rdlength = (buf[offset + 8] << 8) | buf[offset + 9];
        offset += 10;

        if (offset + rdlength > buf_len)
            break;

        if (atype == DNS_TYPE_TXT && aclass == DNS_CLASS_IN)
        {
            return extract_txt_value(buf + offset, rdlength, txt_value, txt_size);
        }

        offset += rdlength;
    }

    return -1;
}

// TXT 记录解析函数
static int resolve_txt_record(const char *input_host, char *resolved_ip, int *resolved_port)
{
    // 去掉 txt: 前缀
    const char *host = input_host + 4;

    // 去掉端口（如果有）
    char hostname[256];
    strncpy(hostname, host, sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';

    // 去掉末尾换行符或空白字符
    trim_right(hostname);

    char *colon = strchr(hostname, ':');
    if (colon)
    {
        *colon = '\0';
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: TXT 记录查询: %s\n", timestamp(), hostname);
    }

    // DNS 服务器列表
    const char *dns_servers[] = {"119.29.29.29", "223.5.5.5", "1.1.1.1"};
    int dns_server_count = 3;

    // 尝试每个 DNS 服务器
    for (int si = 0; si < dns_server_count; si++)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 尝试 DNS 服务器 %d/%d: %s\n",
                    timestamp(), si + 1, dns_server_count, dns_servers[si]);
        }

        // 创建 UDP socket
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: Socket 创建失败: %s\n",
                        timestamp(), strerror(errno));
            }
            continue;
        }

        // 设置超时
        struct timeval tv = {3, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // 构造 DNS 查询
        uint8_t query[512];
        uint16_t txid = (uint16_t)(rand() & 0xFFFF);
        int qlen = build_dns_query(hostname, query, sizeof(query), txid);

        if (qlen < 0)
        {
            close(sock);
            continue;
        }

        // 发送查询
        struct sockaddr_in servaddr = {0};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(53);
        inet_pton(AF_INET, dns_servers[si], &servaddr.sin_addr);

        if (sendto(sock, query, qlen, 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) != qlen)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 发送失败: %s\n", timestamp(), strerror(errno));
            }
            close(sock);
            continue;
        }

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 已发送 %d 字节，等待响应...\n", timestamp(), qlen);
        }

        // 接收响应
        uint8_t resp[2048];
        int recvd = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
        close(sock);

        if (recvd <= 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 接收失败或超时\n", timestamp());
            }
            continue;
        }

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 收到 %d 字节响应\n", timestamp(), recvd);
        }

        // 解析响应
        char txt_value[256];
        if (parse_dns_txt_response(resp, recvd, txid, txt_value, sizeof(txt_value)) == 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: TXT 记录值: %s\n", timestamp(), txt_value);
            }

            // 解析 address:port 格式
            char address[256];
            int port;
            if (sscanf(txt_value, "%255[^:]:%d", address, &port) == 2 &&
                port > 0 && port <= 65535)
            {

                // 检查是否为 IP 地址
                struct in_addr ipv4_addr;
                if (inet_pton(AF_INET, address, &ipv4_addr) == 1)
                {
                    // 是 IP 地址，直接使用
                    strncpy(resolved_ip, address, 255);
                    resolved_ip[255] = '\0';
                    *resolved_port = port;

                    if (verbose)
                    {
                        fprintf(stderr, "[%s] [DEBUG]: TXT 记录解析成功 (IP): %s:%d\n",
                                timestamp(), resolved_ip, *resolved_port);
                    }
                    return 0;
                }
                else
                {
                    // 是主机名，需要解析为 IP
                    struct addrinfo hints = {0};
                    struct addrinfo *result = NULL;
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_DGRAM;

                    if (getaddrinfo(address, NULL, &hints, &result) == 0)
                    {
                        struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
                        inet_ntop(AF_INET, &addr->sin_addr, resolved_ip, 255);
                        *resolved_port = port;
                        freeaddrinfo(result);

                        if (verbose)
                        {
                            fprintf(stderr, "[%s] [DEBUG]: TXT 记录解析成功 (主机名 %s -> IP): %s:%d\n",
                                    timestamp(), address, resolved_ip, *resolved_port);
                        }
                        return 0;
                    }
                    else
                    {
                        if (verbose)
                        {
                            fprintf(stderr, "[%s] [DEBUG]: 无法解析主机名: %s\n", timestamp(), address);
                        }
                    }
                }
            }
            else
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: TXT 记录格式不正确: %s\n", timestamp(), txt_value);
                }
            }
        }
    }

    // if (verbose)
    // {
    fprintf(stderr, "[%s] [ERROR]: 无法解析 %s 的TXT记录\n", timestamp(), hostname);
    //}
    return -1;
}

// 不区分大小写查找 Location 头
static char *find_location_header(const char *response)
{
    const char *p = response;
    while (*p)
    {
        if ((p[0] == 'l' || p[0] == 'L') &&
            (p[1] == 'o' || p[1] == 'O') &&
            (p[2] == 'c' || p[2] == 'C') &&
            (p[3] == 'a' || p[3] == 'A') &&
            (p[4] == 't' || p[4] == 'T') &&
            (p[5] == 'i' || p[5] == 'I') &&
            (p[6] == 'o' || p[6] == 'O') &&
            (p[7] == 'n' || p[7] == 'N') &&
            p[8] == ':')
        {
            return (char *)(p + 9);
        }
        p++;
    }
    return NULL;
}

// 解析地址:端口格式（支持 IP 和主机名）
static int parse_address_port(const char *address_str, char *resolved_ip, int *resolved_port)
{
    char address[256];
    int port;

    if (sscanf(address_str, "%255[^:]:%d", address, &port) != 2 ||
        port <= 0 || port > 65535)
    {
        return -1;
    }

    // 检查是否为 IP 地址
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;

    if (inet_pton(AF_INET, address, &ipv4_addr) == 1 ||
        inet_pton(AF_INET6, address, &ipv6_addr) == 1)
    {
        // 直接使用 IP 地址
        strncpy(resolved_ip, address, 255);
        resolved_ip[255] = '\0';
        *resolved_port = port;
        return 0;
    }

    // 尝试解析为主机名
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(address, NULL, &hints, &result) == 0)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, resolved_ip, 255);
        *resolved_port = port;
        freeaddrinfo(result);
        return 0;
    }

    return -1;
}

// 在响应内容中查找 address:port 格式
static int find_address_in_content(const char *content, char *resolved_ip, int *resolved_port)
{
    // 查找响应体的开始位置（双换行符之后）
    const char *body = strstr(content, "\r\n\r\n");
    if (body)
    {
        body += 4; // 跳过 \r\n\r\n
    }
    else
    {
        body = strstr(content, "\n\n");
        if (body)
        {
            body += 2; // 跳过 \n\n
        }
        else
        {
            body = content; // 如果找不到分隔符，使用整个内容
        }
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 响应体内容: '%s'\n", timestamp(), body);
    }

    const char *p = body; // 从响应体开始查找

    while (*p)
    {
        if (isdigit(*p) || isalpha(*p))
        {
            char candidate[512];
            int i = 0;

            while (*p && !isspace(*p) && (size_t)i < sizeof(candidate) - 1)
            {
                candidate[i++] = *p++;
            }
            candidate[i] = '\0';

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 尝试解析候选: '%s'\n",
                        timestamp(), candidate);
            }

            if (parse_address_port(candidate, resolved_ip, resolved_port) == 0)
            {
                return 0;
            }
        }
        else
        {
            p++;
        }
    }

    return -1;
}

// HTTP 重定向解析函数（支持最多 3 次重定向）
static int resolve_http_redirect(const char *input_host, int input_port,
                                 char *resolved_ip, int *resolved_port)
{
    // 去掉 http: 前缀
    const char *host = input_host + 5; // 跳过 "http:"

    // 解析主机名和端口
    char current_host[256];
    int current_port = input_port;
    char current_path[256] = "/"; // 默认路径为根路径

    strncpy(current_host, host, sizeof(current_host) - 1);
    current_host[sizeof(current_host) - 1] = '\0';

    // 先查找路径分隔符
    char *slash = strchr(current_host, '/');
    if (slash)
    {
        // 保存路径部分
        strncpy(current_path, slash, sizeof(current_path) - 1);
        current_path[sizeof(current_path) - 1] = '\0';
        *slash = '\0'; // 截断主机名部分
    }

    char *colon = strchr(current_host, ':');
    if (colon)
    {
        *colon = '\0';
        current_port = atoi(colon + 1);
    }

    // 如果端口为 0，使用默认 HTTP 端口
    if (current_port == 0)
    {
        current_port = 80;
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: HTTP 重定向查询: %s:%d%s\n",
                timestamp(), current_host, current_port, current_path);
    }

    // 保存最后一次成功解析的完整重定向 URL（不去除路径）
    char last_redirect_url[512] = {0};
    int has_redirect = 0;

    // 最多支持 3 次重定向
    int redirect_count = 0;
    const int MAX_REDIRECTS = 3;

    while (redirect_count < MAX_REDIRECTS)
    {
        // 重试机制:每次重定向尝试 3 次
        int success = 0;
        char response[4096] = {0};
        int http_status = 0;

        for (int retry = 0; retry < 3 && !success; retry++)
        {
            if (verbose && retry > 0)
            {
                fprintf(stderr, "[%s] [DEBUG]: HTTP 请求重试 %d/3\n",
                        timestamp(), retry + 1);
            }

            // 创建 TCP socket
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: Socket 创建失败\n", timestamp());
                }
                continue;
            }

            // 设置超时
            struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            // 解析主机名
            struct addrinfo hints = {0};
            struct addrinfo *result = NULL;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            if (getaddrinfo(current_host, NULL, &hints, &result) != 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 主机名解析失败: %s\n",
                            timestamp(), current_host);
                }
                close(sock);
                continue;
            }

            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(current_port);
            addr.sin_addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
            freeaddrinfo(result);

            // 连接
            if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 连接失败: %s:%d\n",
                            timestamp(), current_host, current_port);
                }
                close(sock);
                continue;
            }

            // 发送 HTTP HEAD 请求(使用完整路径)
            char request[1024];
            snprintf(request, sizeof(request),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     current_path, current_host, current_port);

            if (send(sock, request, strlen(request), 0) < 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 发送请求失败\n", timestamp());
                }
                close(sock);
                continue;
            }

            // 接收响应
            int total_received = 0;
            while ((size_t)total_received < sizeof(response) - 1)
            {
                int n = recv(sock, response + total_received,
                             sizeof(response) - total_received - 1, 0);
                if (n <= 0)
                    break;
                total_received += n;
            }
            response[total_received] = '\0';
            close(sock);

            if (total_received > 0)
            {
                success = 1;

                // 解析 HTTP 状态码
                if (sscanf(response, "HTTP/1.%*d %d", &http_status) != 1)
                {
                    http_status = 0;
                }

                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 收到 %d 字节 HTTP 响应，状态码: %d\n",
                            timestamp(), total_received, http_status);
                    fprintf(stderr, "[%s] [DEBUG]: HTTP 响应内容:\n%s\n",
                            timestamp(), response);
                }
                break;
            }

            if (retry < 2)
            {
                usleep(500000); // 等待 0.5 秒后重试
            }
        }

        if (!success)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: HTTP 请求失败(已重试 3 次)\n",
                        timestamp());
            }
            break; // 退出重定向循环
        }

        // 查找 Location 头(不区分大小写)
        char *location = find_location_header(response);

        if (location)
        {
            // 找到重定向地址
            char redirect_url[512];
            int i = 0;

            // 跳过空格
            while (*location == ' ')
                location++;

            // 提取完整 URL(直到换行)，不去除路径
            while (*location && *location != '\r' && *location != '\n' &&
                   (size_t)i < sizeof(redirect_url) - 1)
            {
                redirect_url[i++] = *location++;
            }
            redirect_url[i] = '\0';

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 重定向 %d/%d: %s\n",
                        timestamp(), redirect_count + 1, MAX_REDIRECTS, redirect_url);
            }

            // 保存这个重定向 URL（完整的，包含路径）
            strncpy(last_redirect_url, redirect_url, sizeof(last_redirect_url) - 1);
            last_redirect_url[sizeof(last_redirect_url) - 1] = '\0';
            has_redirect = 1;

            // 解析重定向 URL 以准备下一次请求
            char *url_start = redirect_url;
            if (strncmp(url_start, "http://", 7) == 0)
            {
                url_start += 7;
            }
            else if (strncmp(url_start, "https://", 8) == 0)
            {
                url_start += 8;
            }

            // 分离主机名和路径
            char *slash_pos = strchr(url_start, '/');
            if (slash_pos)
            {
                // 保存路径
                strncpy(current_path, slash_pos, sizeof(current_path) - 1);
                current_path[sizeof(current_path) - 1] = '\0';
                *slash_pos = '\0'; // 临时截断以解析主机名
            }
            else
            {
                strcpy(current_path, "/"); // 默认根路径
            }

            // 解析主机名和端口
            strncpy(current_host, url_start, sizeof(current_host) - 1);
            current_host[sizeof(current_host) - 1] = '\0';

            char *colon_pos = strchr(current_host, ':');
            if (colon_pos)
            {
                *colon_pos = '\0';
                current_port = atoi(colon_pos + 1);
            }
            else
            {
                current_port = 80; // 默认 HTTP 端口
            }

            redirect_count++;
            continue; // 继续下一次重定向
        }

        // 没有 Location 头
        if (http_status == 200)
        {
            // 200 响应但没有重定向，尝试从响应内容中查找 address:port
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 收到 200 响应但无 Location 头，尝试解析响应内容\n",
                        timestamp());
                fprintf(stderr, "[%s] [DEBUG]: 响应内容: %s\n", timestamp(), response);
            }

            char temp_ip[256];
            int temp_port;
            if (find_address_in_content(response, temp_ip, &temp_port) == 0)
            {
                // 从响应内容找到了地址
                strncpy(resolved_ip, temp_ip, 255);
                resolved_ip[255] = '\0';
                *resolved_port = temp_port;

                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 从 200 响应内容解析到地址: %s:%d\n",
                            timestamp(), temp_ip, temp_port);
                }
                return 0;
            }
        }

        // 没有找到重定向，退出循环
        break;
    }

    // 处理最终结果
    if (has_redirect)
    {
        // 有重定向记录，使用最后一次重定向的 URL
        char *url_start = last_redirect_url;

        // 去除 http:// 或 https:// 前缀
        if (strncmp(url_start, "http://", 7) == 0)
        {
            url_start += 7;
        }
        else if (strncmp(url_start, "https://", 8) == 0)
        {
            url_start += 8;
        }

        // 去除路径部分（只保留主机:端口）
        char *slash_pos = strchr(url_start, '/');
        if (slash_pos)
        {
            *slash_pos = '\0';
        }

        // 解析为 address:port
        if (parse_address_port(url_start, resolved_ip, resolved_port) == 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: HTTP 重定向最终解析: %s:%d\n",
                        timestamp(), resolved_ip, *resolved_port);
            }
            return 0;
        }
    }

    // 没有重定向也没有从响应内容解析到地址
    // if (verbose) {
    fprintf(stderr, "[%s] [ERROR]: 无法获取 %s 的重定向地址或响应内容\n",
            timestamp(), input_host);
    //}
    return -1;
}

// 生成 HTML 页面
void generate_html(char *buf, size_t bufsize)
{
    // 如果开启详细模式，输出调试信息（中文注释）
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 开始生成 HTML 页面\n", timestamp());
    }
    pthread_rwlock_rdlock(&g_state.lock);

    time_t now = time(NULL);
    time_t uptime = now - g_state.start_time;

    // 智能格式化运行时间（中文注释）
    char uptime_str[256] = "";
    int has_content = 0;
    char interval_str[256] = "";
    int interval_seconds = g_state.check_interval_minutes * 60;
    int has_interval_content = 0;

    // 计算各个时间单位
    int years = uptime / (365 * 24 * 3600);
    uptime %= (365 * 24 * 3600);
    int interval_years = interval_seconds / (365 * 24 * 3600);
    interval_seconds %= (365 * 24 * 3600);

    int months = uptime / (30 * 24 * 3600);
    uptime %= (30 * 24 * 3600);
    int interval_months = interval_seconds / (30 * 24 * 3600);
    interval_seconds %= (30 * 24 * 3600);

    int weeks = uptime / (7 * 24 * 3600);
    uptime %= (7 * 24 * 3600);

    int days = uptime / (24 * 3600);
    uptime %= (24 * 3600);
    int interval_days = interval_seconds / (24 * 3600);
    interval_seconds %= (24 * 3600);

    int hours = uptime / 3600;
    uptime %= 3600;
    int interval_hours = interval_seconds / 3600;
    interval_seconds %= 3600;

    int minutes = uptime / 60;
    int seconds = uptime % 60;
    int interval_minutes = interval_seconds / 60;
    int interval_secs = interval_seconds % 60;

    // 只显示有值的单位
    if (years > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%d年", years);
        has_content = 1;
    }
    if (interval_years > 0)
    {
        snprintf(interval_str + strlen(interval_str), sizeof(interval_str) - strlen(interval_str),
                 "%d年", interval_years);
        has_interval_content = 1;
    }
    if (months > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d月", has_content ? " " : "", months);
        has_content = 1;
    }
    if (interval_months > 0)
    {
        snprintf(interval_str + strlen(interval_str), sizeof(interval_str) - strlen(interval_str),
                 "%s%d个月", has_interval_content ? " " : "", interval_months);
        has_interval_content = 1;
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
    if (interval_days > 0)
    {
        snprintf(interval_str + strlen(interval_str), sizeof(interval_str) - strlen(interval_str),
                 "%s%d天", has_interval_content ? " " : "", interval_days);
        has_interval_content = 1;
    }
    if (hours > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d时", has_content ? " " : "", hours);
        has_content = 1;
    }
    if (interval_hours > 0)
    {
        snprintf(interval_str + strlen(interval_str), sizeof(interval_str) - strlen(interval_str),
                 "%s%d小时", has_interval_content ? " " : "", interval_hours);
        has_interval_content = 1;
    }
    if (minutes > 0)
    {
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d分", has_content ? " " : "", minutes);
        has_content = 1;
    }
    if (interval_minutes > 0)
    {
        snprintf(interval_str + strlen(interval_str), sizeof(interval_str) - strlen(interval_str),
                 "%s%d分钟", has_interval_content ? " " : "", interval_minutes);
        has_interval_content = 1;
    }
    if (seconds > 0 || !has_content)
    { // 如果所有单位都是0,至少显示秒
        snprintf(uptime_str + strlen(uptime_str), sizeof(uptime_str) - strlen(uptime_str),
                 "%s%d秒", has_content ? " " : "", seconds);
    }
    if (interval_secs > 0 || !has_interval_content)
    {
        snprintf(interval_str + strlen(interval_str), sizeof(interval_str) - strlen(interval_str),
                 "%s%d秒", has_interval_content ? " " : "", interval_secs);
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

    // 页面刷新间隔等于检测间隔(秒),但最小为15分钟
    int refresh_seconds = g_state.check_interval_minutes * 60;
    if (refresh_seconds < 900)
    {
        refresh_seconds = 900; // 最小15分钟
    }

    int len = snprintf(buf, bufsize,
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
                       "tbody td{padding:12px;border-bottom:1px solid #f3f4f6;vertical-align:middle;text-align:center;transition:all 0.2s ease;}\n"
                       "tr:hover td{background:#f9fafb;transform:scale(1.01);}\n"
                       "tr{transition:all 0.2s ease;}\n"
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
                       ".progress-bar-bg{position:absolute;left:0;top:0;height:100%%;transition:width 0.3s ease;min-width:100%%;}\n"                                                                                                                                                                          // 添加 min-width:100%%  // 新增背景层
                       ".progress-bar-text{position:absolute;left:0;top:0;width:100%%;height:100%%;display:flex;align-items:center;justify-content:center;color:white;font-size:12px;font-weight:700;z-index:1;}\n"                                                                                           // 新增文字层
                       ".tooltip{position:fixed;background:rgba(31,41,55,0.95);color:white;padding:10px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,0.2);z-index:1001;pointer-events:none;max-width:400px;transform:translateY(6px);opacity:0;transition:opacity 180ms ease,transform 180ms ease}\n" // 增加 tooltip 的 max-width
                       ".tooltip.show{opacity:1;transform:translateY(0)}\n"
                       ".tooltip-title{font-weight:700;margin-bottom:6px;}\n"
                       ".tooltip-history{display:flex;gap:4px;flex-wrap:wrap;max-height:60px;overflow:hidden;max-width:360px;}\n" // 添加 max-width
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
                       ".history-item-time{line-height:1.4;}\n"
                       ".history-item-date{font-size:10px;font-weight:600;color:var(--muted);}\n"
                       ".history-item-hour{font-size:14px;font-weight:700;color:#0284c7;}\n"
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
                       ".date-picker-overlay{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,0.5);backdrop-filter:blur(4px);z-index:2001}\n"
                       ".date-picker-overlay.active{display:flex}\n"
                       ".date-picker-content{background:white;border-radius:12px;padding:20px;max-width:360px;width:92%%;box-shadow:0 20px 60px rgba(0,0,0,0.3);}\n"
                       ".date-picker-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;}\n"
                       ".date-picker-nav{background:transparent;border:none;cursor:pointer;padding:8px;font-size:18px;color:var(--text);}\n"
                       ".date-picker-nav:hover{background:#f3f4f6;border-radius:6px;}\n"
                       ".date-picker-month{font-size:16px;font-weight:700;color:var(--text);}\n"
                       ".date-picker-grid{display:grid;grid-template-columns:repeat(7,1fr);gap:4px;margin-bottom:16px;}\n"
                       ".date-picker-day{padding:8px;text-align:center;border-radius:6px;cursor:pointer;font-size:14px;}\n"
                       ".date-picker-day.disabled{color:#d1d5db;cursor:not-allowed;}\n"
                       ".date-picker-day.has-data{background:#dbeafe;color:#0369a1;font-weight:600;}\n"
                       ".date-picker-day.has-data:hover{background:#bfdbfe;}\n"
                       ".date-picker-day.selected{background:var(--accent);color:white;}\n"
                       ".date-picker-weekday{padding:8px;text-align:center;font-size:12px;color:var(--muted);font-weight:600;}\n"
                       ".date-picker-actions{display:flex;gap:8px;justify-content:flex-end;}\n"
                       ".date-picker-btn{padding:8px 16px;border-radius:8px;cursor:pointer;font-weight:600;border:1px solid var(--border);}\n"
                       ".date-picker-btn.primary{background:var(--accent);color:white;border:none;}\n"
                       ".date-picker-btn.primary:hover{opacity:0.9;}\n"
                       ".date-picker-btn.secondary{background:white;color:var(--text);}\n"
                       ".date-picker-btn.secondary:hover{background:#f3f4f6;}\n"
                       "@keyframes history-pulse {\n"
                       "  0%%, 100%% { background: transparent; }\n"
                       "  50%% { background: #a855f7; }\n"
                       "}\n"
                       ".history-item-pulse{animation:history-pulse 0.5s ease-in-out 5;}\n"
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
                       "    var showVersion = (versionFilter === 'all');\n"
                       "    if (!showVersion) {\n"
                       "      var badges = versionCell.split(/\\s+/);\n"
                       "      for (var j = 0; j < badges.length; j++) {\n"
                       "        if (badges[j] === versionFilter) {\n"
                       "          showVersion = true;\n"
                       "          break;\n"
                       "        }\n"
                       "      }\n"
                       "    }\n"
                       "    var showStatus = (statusFilter === 'all' || \n"
                       "                     (statusFilter === 'online' && statusCell.includes('在线')) ||\n"
                       "                     (statusFilter === 'offline' && statusCell.includes('离线')));\n"
                       "    row.style.display = (showVersion && showStatus) ? '' : 'none';\n"
                       "  }\n"
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
                       "function processHistoryData(historyData) {\n"
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
                       "  return sortedRecords;\n"
                       "}\n"
                       "\n"
                       "function showHistoryTooltip(event, historyData) {\n"
                       "  if (!tooltip) {\n"
                       "    tooltip = document.createElement('div');\n"
                       "    tooltip.className = 'tooltip';\n"
                       "    document.body.appendChild(tooltip);\n"
                       "  }\n"
                       "  \n"
                       "  var html = '<div class=\"tooltip-title\">最近60次检测记录</div>';\n"
                       "  html += '<div class=\"tooltip-history\">';\n"
                       "  \n"
                       "  // 使用共享函数获取排序后的记录\n"
                       "  var sortedRecords = processHistoryData(historyData);\n"
                       "  \n"
                       "  // 只取最新60条\n"
                       "  var maxDisplay = 60;\n"
                       "  var displayRecords = sortedRecords.slice(0, maxDisplay);\n"
                       "  \n"
                       "  // 反转数组,从旧到新显示(最新的在右边)\n"
                       "  displayRecords.reverse();\n"
                       "  \n"
                       "  // 生成HTML\n"
                       "  for (var i = 0; i < displayRecords.length; i++) {\n"
                       "    var record = displayRecords[i];\n"
                       "    var status = record.status ? 'history-online' : 'history-offline';\n"
                       "    html += '<div class=\"history-bar ' + status + '\"></div>';\n"
                       "  }\n"
                       "  \n"
                       "  html += '</div>';\n"
                       "  tooltip.innerHTML = html;\n"
                       "  \n"
                       "  // 获取触发元素的位置\n"
                       "  var target = event.currentTarget || event.target;\n"
                       "  var rect = target.getBoundingClientRect();\n"
                       "  \n"
                       "  // 临时显示以获取实际尺寸\n"
                       "  tooltip.style.visibility = 'hidden';\n"
                       "  tooltip.style.display = 'block';\n"
                       "  tooltip.style.opacity = '0';\n"
                       "  var tooltipRect = tooltip.getBoundingClientRect();\n"
                       "  \n"
                       "  // 计算位置 (优先显示在下方)\n"
                       "  var left = rect.left + (rect.width - tooltipRect.width) / 2;\n"
                       "  var top = rect.bottom + 8;\n"
                       "  \n"
                       "  // 检查下方空间是否足够\n"
                       "  if (top + tooltipRect.height > window.innerHeight) {\n"
                       "    // 下方空间不足,显示在上方\n"
                       "    top = rect.top - tooltipRect.height - 8;\n"
                       "  }\n"
                       "  \n"
                       "  // 水平边界检查\n"
                       "  if (left < 12) left = 12;\n"
                       "  if (left + tooltipRect.width > window.innerWidth - 12) {\n"
                       "    left = window.innerWidth - tooltipRect.width - 12;\n"
                       "  }\n"
                       "  \n"
                       "  // 应用位置 (使用 fixed 定位)\n"
                       "  tooltip.style.position = 'fixed';\n"
                       "  tooltip.style.left = left + 'px';\n"
                       "  tooltip.style.top = top + 'px';\n"
                       "  tooltip.style.visibility = '';\n"
                       "  tooltip.style.opacity = '';\n"
                       "  tooltip.classList.add('show');\n"
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
                       "  html += '<div style=\"display:flex;gap:8px;align-items:center;\">';\n"
                       "  html += '<div class=\"modal-title\">' + host + (port ? ':' + port : '') + ' 历史检测记录</div>';\n"
                       "  html += '<button onclick=\"showDatePicker(\\'' + host + '\\',\\'' + port + '\\',\\'' + historyData + '\\')\" style=\"background:transparent;border:none;cursor:pointer;padding:4px;\" title=\"选择日期\">';\n"
                       "  html += '<svg width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"3\" y=\"4\" width=\"18\" height=\"18\" rx=\"2\" ry=\"2\"/><line x1=\"16\" y1=\"2\" x2=\"16\" y2=\"6\"/><line x1=\"8\" y1=\"2\" x2=\"8\" y2=\"6\"/><line x1=\"3\" y1=\"10\" x2=\"21\" y2=\"10\"/></svg>';\n"
                       "  html += '</button>';\n"
                       "  html += '<select id=\"historyStatusFilter\" onchange=\"filterHistoryByStatus()\" style=\"padding:4px 8px;border-radius:6px;border:1px solid var(--border);background:white;color:var(--text);font-size:12px;cursor:pointer;\">';\n"
                       "  html += '<option value=\"all\">全部</option>';\n"
                       "  html += '<option value=\"online\">只看在线</option>';\n"
                       "  html += '<option value=\"offline\">只看离线</option>';\n"
                       "  html += '</select>';\n"
                       "  html += '</div>';\n"
                       "  html += '<button class=\"modal-close\" onclick=\"closeHistoryModal()\">×</button>';\n"
                       "  html += '</div>';\n"
                       "  html += '<div class=\"history-grid\">';\n"
                       "  \n"
                       "  // 使用共享函数获取排序后的记录\n"
                       "  var sortedRecords = processHistoryData(historyData);\n"
                       "  \n"
                       "  // 生成 HTML (从新到旧显示,按日期分组)\n"
                       "  var lastDate = '';\n"
                       "  for (var i = 0; i < sortedRecords.length; i++) {\n"
                       "    var record = sortedRecords[i];\n"
                       "    var date = new Date(record.timestamp * 1000);\n"
                       "    var currentDate = date.getFullYear() + '年' + \n"
                       "                     (date.getMonth() + 1) + '月' + \n"
                       "                     date.getDate() + '日';\n"
                       "    \n"
                       "    // 如果日期变化,添加日期段落\n"
                       "    if (currentDate !== lastDate) {\n"
                       "      html += '<div class=\"date-separator\" data-date=\"' + date.getFullYear() + '-' + (date.getMonth() + 1) + '-' + date.getDate() + '\" style=\"grid-column: 1 / -1; padding: 8px 0; font-weight: 700; color: var(--text); background: #f3f4f6; border-radius: 6px; text-align: center;\">' + \n"
                       "              currentDate + '</div>';\n"
                       "      lastDate = currentDate;\n"
                       "    }\n"
                       "    \n"
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
                       "    var statusClass = record.status ? 'online' : 'offline';\n"
                       "    \n"
                       "    // 添加 data-status 属性用于筛选\n"
                       "    html += '<div class=\"history-item\" data-status=\"' + statusClass + '\" title=\"' + fullDateStr + ' ' + statusText + '\">';\n"
                       "    html += '<div class=\"history-item-bar ' + statusClass + '\" style=\"background:' + (record.status ? 'linear-gradient(90deg,#34d399,#10b981)' : 'linear-gradient(90deg,#fb7185,#ef4444)') + '\"></div>';\n"
                       "    html += '<div class=\"history-item-time\">';\n"
                       "    html += '<div class=\"history-item-date\">' + dateStr + '</div>';\n"
                       "    html += '<div class=\"history-item-hour\">' + timeStr + '</div>';\n"
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
                       "var selectedDate = null;\n"
                       "var availableDates = {};\n"
                       "function showDatePicker(host, port, historyData) {\n"
                       "  var picker = document.getElementById('datePicker');\n"
                       "  if (!picker) {\n"
                       "    picker = document.createElement('div');\n"
                       "    picker.id = 'datePicker';\n"
                       "    picker.className = 'date-picker-overlay';\n"
                       "    document.body.appendChild(picker);\n"
                       "  }\n"
                       "  \n"
                       "  // 解析历史数据,获取所有有记录的日期\n"
                       "  availableDates = {};\n"
                       "  var sortedRecords = processHistoryData(historyData);\n"
                       "  for (var i = 0; i < sortedRecords.length; i++) {\n"
                       "    var date = new Date(sortedRecords[i].timestamp * 1000);\n"
                       "    var dateKey = date.getFullYear() + '-' + (date.getMonth() + 1) + '-' + date.getDate();\n"
                       "    availableDates[dateKey] = true;\n"
                       "  }\n"
                       "  \n"
                       "  // 初始化为当前月份\n"
                       "  var now = new Date();\n"
                       "  renderDatePicker(now.getFullYear(), now.getMonth(), host, port, historyData);\n"
                       "  picker.className = 'date-picker-overlay active';\n"
                       "  picker.onclick = function(e) { if (e.target === picker) closeDatePicker(); };\n"
                       "}\n"
                       "\n"
                       "function renderDatePicker(year, month, host, port, historyData) {\n"
                       "  var picker = document.getElementById('datePicker');\n"
                       "  var monthNames = ['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月'];\n"
                       "  \n"
                       "  var html = '<div class=\"date-picker-content\" onclick=\"event.stopPropagation()\">';\n"
                       "  html += '<div class=\"date-picker-header\">';\n"
                       "  html += '<button class=\"date-picker-nav\" onclick=\"changeMonth(-1,' + year + ',' + month + ',\\'' + host + '\\',\\'' + port + '\\',\\'' + historyData + '\\')\">&lt;</button>';\n"
                       "  html += '<div class=\"date-picker-month\">' + year + '年 ' + monthNames[month] + '</div>';\n"
                       "  html += '<button class=\"date-picker-nav\" onclick=\"changeMonth(1,' + year + ',' + month + ',\\'' + host + '\\',\\'' + port + '\\',\\'' + historyData + '\\')\">&gt;</button>';\n"
                       "  html += '</div>';\n"
                       "  \n"
                       "  // 星期标题\n"
                       "  html += '<div class=\"date-picker-grid\">';\n"
                       "  var weekdays = ['日','一','二','三','四','五','六'];\n"
                       "  for (var i = 0; i < 7; i++) {\n"
                       "    html += '<div class=\"date-picker-weekday\">' + weekdays[i] + '</div>';\n"
                       "  }\n"
                       "  \n"
                       "  // 计算当月第一天是星期几\n"
                       "  var firstDay = new Date(year, month, 1).getDay();\n"
                       "  var daysInMonth = new Date(year, month + 1, 0).getDate();\n"
                       "  \n"
                       "  // 填充空白\n"
                       "  for (var i = 0; i < firstDay; i++) {\n"
                       "    html += '<div></div>';\n"
                       "  }\n"
                       "  \n"
                       "  // 填充日期\n"
                       "  for (var day = 1; day <= daysInMonth; day++) {\n"
                       "    var dateKey = year + '-' + (month + 1) + '-' + day;\n"
                       "    var hasData = availableDates[dateKey];\n"
                       "    var classes = 'date-picker-day';\n"
                       "    if (!hasData) classes += ' disabled';\n"
                       "    else classes += ' has-data';\n"
                       "    if (selectedDate === dateKey) classes += ' selected';\n"
                       "    \n"
                       "    var onclick = hasData ? 'selectDate(\\'' + dateKey + '\\', event)' : '';\n"
                       "    html += '<div class=\"' + classes + '\" onclick=\"' + onclick + '\">' + day + '</div>';\n"
                       "  }\n"
                       "  \n"
                       "  html += '</div>';\n"
                       "  \n"
                       "  // 操作按钮\n"
                       "  html += '<div class=\"date-picker-actions\">';\n"
                       "  html += '<button class=\"date-picker-btn secondary\" onclick=\"closeDatePicker()\">取消</button>';\n"
                       "  html += '<button class=\"date-picker-btn primary\" onclick=\"confirmDateSelection(\\'' + host + '\\',\\'' + port + '\\',\\'' + historyData + '\\')\" ' + (selectedDate ? '' : 'disabled') + '>确定</button>';\n"
                       "  html += '</div>';\n"
                       "  html += '</div>';\n"
                       "  \n"
                       "  picker.innerHTML = html;\n"
                       "}\n"
                       "\n"
                       "function changeMonth(delta, year, month, host, port, historyData) {\n"
                       "  month += delta;\n"
                       "  if (month < 0) { month = 11; year--; }\n"
                       "  if (month > 11) { month = 0; year++; }\n"
                       "  renderDatePicker(year, month, host, port, historyData);\n"
                       "}\n"
                       "\n"
                       "function selectDate(dateKey, event) {\n"
                       "  selectedDate = dateKey;\n"
                       "  // 重新渲染以更新选中状态\n"
                       "  var picker = document.getElementById('datePicker');\n"
                       "  var days = picker.querySelectorAll('.date-picker-day');\n"
                       "  days.forEach(function(day) {\n"
                       "    day.classList.remove('selected');\n"
                       "  });\n"
                       "  if (event && event.target) {\n"
                       "    event.target.classList.add('selected');\n"
                       "  }\n"
                       "  // 启用确定按钮\n"
                       "  var confirmBtn = picker.querySelector('.date-picker-btn.primary');\n"
                       "  if (confirmBtn) confirmBtn.disabled = false;\n"
                       "}\n"
                       "\n"
                       "function confirmDateSelection(host, port, historyData) {\n"
                       "  if (!selectedDate) return;\n"
                       "  \n"
                       "  var savedDate = selectedDate;\n"
                       "  closeDatePicker();\n"
                       "  \n"
                       "  setTimeout(function() {\n"
                       "    var modal = document.getElementById('historyModal');\n"
                       "    var scrollContainer = modal.querySelector('.history-grid');\n"
                       "    var dateSeparator = modal.querySelector('.date-separator[data-date=\"' + savedDate + '\"]');\n"
                       "    \n"
                       "    if (dateSeparator && scrollContainer) {\n"
                       "      // 找到日期分隔符后的最后一个可见的历史记录项(时间最早)\n"
                       "      var targetItem = null;\n"
                       "      var children = scrollContainer.children;\n"
                       "      var foundSeparator = false;\n"
                       "      \n"
                       "      for (var i = 0; i < children.length; i++) {\n"
                       "        if (children[i] === dateSeparator) {\n"
                       "          foundSeparator = true;\n"
                       "          continue;\n"
                       "        }\n"
                       "        \n"
                       "        // 只选择可见的 history-item\n"
                       "        if (foundSeparator && children[i].classList.contains('history-item') && \n"
                       "            children[i].style.display !== 'none') {\n"
                       "          targetItem = children[i];  // 持续更新,保留最后一个可见的\n"
                       "        }\n"
                       "        \n"
                       "        if (foundSeparator && children[i].classList.contains('date-separator')) {\n"
                       "          break;\n"
                       "        }\n"
                       "      }\n"
                       "      \n"
                       "      if (targetItem) {\n"
                       "        // 计算滚动位置\n"
                       "        var containerRect = scrollContainer.getBoundingClientRect();\n"
                       "        var targetRect = targetItem.getBoundingClientRect();\n"
                       "        var scrollOffset = targetRect.top - containerRect.top + scrollContainer.scrollTop;\n"
                       "        \n"
                       "        scrollContainer.scrollTo({\n"
                       "          top: scrollOffset,\n"
                       "          behavior: 'smooth'\n"
                       "        });\n"
                       "        \n"
                       "        // 添加紫色闪烁动画(5次)\n"
                       "        targetItem.classList.add('history-item-pulse');\n"
                       "        \n"
                       "        setTimeout(function() {\n"
                       "          targetItem.classList.remove('history-item-pulse');\n"
                       "        }, 2500);\n"
                       "      }\n"
                       "    }\n"
                       "  }, 500);\n"
                       "}\n"
                       "\n"
                       "function closeDatePicker() {\n"
                       "  var picker = document.getElementById('datePicker');\n"
                       "  if (picker) {\n"
                       "    picker.className = 'date-picker-overlay';\n"
                       "    selectedDate = null;\n"
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
                       "  var offlineHosts = [];\n" // 改为数组
                       "  for (var i=1;i<rows.length;i++){\n"
                       "    if (rows[i].style.display === 'none') continue;\n"
                       "    total++;\n"
                       "    var s = rows[i].cells[4].textContent || '';\n"
                       "    if (s.indexOf('离线') !== -1) {\n"
                       "      offline++;\n"
                       "      offlineHosts.push({\n"
                       "        host: rows[i].getAttribute('data-host'),\n"
                       "        port: rows[i].getAttribute('data-port')\n"
                       "      });\n"
                       "    }\n"
                       "  }\n"
                       "  var noticeEl = document.getElementById('topNotice');\n"
                       "  if (!noticeEl) return;\n"
                       "  if (offline > 0) {\n"
                       "    noticeEl.className = 'top-notice card notice-warn';\n"
                       "    noticeEl.innerHTML = '<div class=\"notice-left\"><div class=\"notice-dot\" style=\"background:linear-gradient(90deg,#fb7185,#ef4444)\"></div><div><div style=\"font-weight:800\">存在异常服务</div><div class=\"sub\">发现 '+offline+' 个服务异常，请尽快检查</div></div></div><div><button class=\"notice-btn\" onclick=\"scrollToAllOfflineHosts()\">查看详情</button></div>';\n"
                       "  } else {\n"
                       "    noticeEl.className = 'top-notice card notice-ok';\n"
                       "    noticeEl.innerHTML = '<div class=\"notice-left\"><div class=\"notice-dot\" style=\"background:linear-gradient(90deg,#34d399,#10b981)\"></div><div><div style=\"font-weight:800\">所有服务状态正常</div><div class=\"sub\">当前 '+total+' 个服务全部在线</div></div></div><div></div>';\n"
                       "  }\n"
                       "  window.offlineHostsList = offlineHosts;\n"
                       "}\n"
                       "function scrollToTable(){ var el = document.querySelector('.table-wrap'); if(el) el.scrollIntoView({behavior:'smooth',block:'start'}); }\n"
                       "\n"
                       "function scrollToHost(host, port) {\n"
                       "  var rowId = 'host-' + host.replace(/\\./g, '-').replace(/:/g, '-').replace(/\\//g, '-') + '-' + port;\n" // 替换点号为连字符
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
                       "function filterHistoryByStatus() {\n"
                       "  var filter = document.getElementById('historyStatusFilter').value;\n"
                       "  var modal = document.getElementById('historyModal');\n"
                       "  var items = modal.querySelectorAll('.history-item');\n"
                       "  var separators = modal.querySelectorAll('.date-separator');\n"
                       "  \n"
                       "  // 先显示所有项\n"
                       "  items.forEach(function(item) {\n"
                       "    if (filter === 'all') {\n"
                       "      item.style.display = '';\n"
                       "    } else {\n"
                       "      var status = item.getAttribute('data-status');\n"
                       "      item.style.display = (status === filter) ? '' : 'none';\n"
                       "    }\n"
                       "  });\n"
                       "  \n"
                       "  // 处理日期分隔符的显示/隐藏\n"
                       "  separators.forEach(function(separator) {\n"
                       "    var nextElement = separator.nextElementSibling;\n"
                       "    var hasVisibleItems = false;\n"
                       "    \n"
                       "    // 检查该日期分隔符后是否有可见的历史记录项\n"
                       "    while (nextElement && !nextElement.classList.contains('date-separator')) {\n"
                       "      if (nextElement.classList.contains('history-item') && nextElement.style.display !== 'none') {\n"
                       "        hasVisibleItems = true;\n"
                       "        break;\n"
                       "      }\n"
                       "      nextElement = nextElement.nextElementSibling;\n"
                       "    }\n"
                       "    \n"
                       "    // 如果该日期下没有可见项,隐藏日期分隔符\n"
                       "    separator.style.display = hasVisibleItems ? '' : 'none';\n"
                       "  });\n"
                       "}\n"
                       "function scrollToAllOfflineHosts() {\n"
                       "  if (!window.offlineHostsList || window.offlineHostsList.length === 0) return;\n"
                       "  var firstHost = window.offlineHostsList[0];\n"
                       "  var firstRowId = 'host-' + firstHost.host.replace(/\\./g, '-').replace(/:/g, '-').replace(/\\//g, '-') + '-' + firstHost.port;\n"
                       "  var firstRow = document.getElementById(firstRowId);\n"
                       "  if (firstRow) {\n"
                       "    firstRow.scrollIntoView({ behavior: 'smooth', block: 'center' });\n"
                       "  }\n"
                       "  setTimeout(function() {\n"
                       "    for (var i = 0; i < window.offlineHostsList.length; i++) {\n"
                       "      var host = window.offlineHostsList[i];\n"
                       "      var rowId = 'host-' + host.host.replace(/\\./g, '-').replace(/:/g, '-').replace(/\\//g, '-') + '-' + host.port;\n"
                       "      var row = document.getElementById(rowId);\n"
                       "      if (row) {\n"
                       "        row.classList.add('blink-highlight');\n"
                       "      }\n"
                       "    }\n"
                       "    setTimeout(function() {\n"
                       "      for (var i = 0; i < window.offlineHostsList.length; i++) {\n"
                       "        var host = window.offlineHostsList[i];\n"
                       "        var rowId = 'host-' + host.host.replace(/\\./g, '-').replace(/:/g, '-').replace(/\\//g, '-') + '-' + host.port;\n"
                       "        var row = document.getElementById(rowId);\n"
                       "        if (row) {\n"
                       "          row.classList.remove('blink-highlight');\n"
                       "        }\n"
                       "      }\n"
                       "    }, 3000);\n"
                       "  }, 500);\n"
                       "}\n"
                       "function manualRefresh() { \n"
                       "var btn = document.getElementById('refreshBtn');\n"
                       "btn.disabled = true; \n"
                       "btn.style.opacity = '0.6';\n"
                       "btn.style.transform = 'scale(0.95)';\n"
                       "btn.textContent = '检测中...';\n"
                       "fetch('/refresh')\n"
                       ".then(response => response.json())\n"
                       ".then(data => {\n"
                       "if (data.success) {\n"
                       "showToast('检测成功', true);\n"
                       "setTimeout(() => location.reload(), 1000);\n"
                       "} else {\n"
                       "showToast(data.message, false);\n"
                       "btn.disabled = false;\n"
                       "btn.style.opacity = '1';\n"
                       "btn.style.transform = 'scale(1)';\n"
                       "btn.textContent = '立即检测';\n"
                       "}\n"
                       "})\n"
                       ".catch(err => {\n"
                       "showToast('检测失败,请稍后重试', false);\n"
                       "btn.disabled = false;\n"
                       "btn.style.opacity = '1';\n"
                       "btn.style.transform = 'scale(1)';\n"
                       "btn.textContent = '立即检测';\n"
                       "});\n"
                       "}\n"
                       "function openTestMyModal() {\n"
                       "  var modal = document.getElementById('testMyModal');\n"
                       "  if (!modal) {\n"
                       "    modal = document.createElement('div');\n"
                       "    modal.id = 'testMyModal';\n"
                       "    modal.className = 'modal-overlay';\n"
                       "    modal.innerHTML = '<div class=\"modal-content\" onclick=\"event.stopPropagation()\" style=\"max-width:min(92%%,520px);min-width:380px;width:auto;\">' +\n"
                       "      '<div class=\"modal-header\">' +\n"
                       "      '<div class=\"modal-title\">测测我的服务器</div>' +\n"
                       "      '<button class=\"modal-close\" onclick=\"closeTestMyModal()\">×</button>' +\n"
                       "      '</div>' +\n"
                       "      '<div style=\"padding:16px;\">' +\n"
                       "      '<input type=\"text\" id=\"testMyInput\" placeholder=\"请输入您的服务器地址 (如: n2n.example.com:10086)\" ' +\n"
                       "      'style=\"width:100%%;padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:12px;box-sizing:border-box;\">' +\n"
                       "      '<div style=\"text-align:center;\">' +\n"
                       "      '<button onclick=\"testMyServer()\" style=\"padding:8px 16px;background:var(--accent);color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;display:inline-block;width:auto;\">检测</button>' +\n"
                       "      '</div>' +\n"
                       "      '<div id=\"testMyResult\" style=\"margin-top:12px;\"></div>' +\n"
                       "      '</div>' +\n"
                       "      '</div>';\n"
                       "    document.body.appendChild(modal);\n"
                       "  }\n"
                       "  modal.classList.add('active');\n"
                       "}\n"
                       "function closeTestMyModal() {\n"
                       "  var modal = document.getElementById('testMyModal');\n"
                       "  if (modal) modal.classList.remove('active');\n"
                       "}\n"
                       "function testMyServer() {\n"
                       "  var input = document.getElementById('testMyInput').value.trim();\n"
                       "  var resultDiv = document.getElementById('testMyResult');\n"
                       "  if (!input) {\n"
                       "    resultDiv.innerHTML = '<div style=\"color:var(--danger);\">请输入服务器地址</div>';\n"
                       "    return;\n"
                       "  }\n"
                       "  resultDiv.innerHTML = '<div style=\"color:var(--muted);\">检测中...</div>';\n"
                       "  fetch('/testmy?address=' + encodeURIComponent(input))\n"
                       "    .then(function(response) { return response.json(); })\n"
                       "    .then(function(data) {\n"
                       "      if (data.is_mine) {\n"
                       "        resultDiv.innerHTML = '<div style=\"color:var(--danger);font-weight:600;text-align:center;padding:20px;\">已经存在的主机，请勿重复检测!</div>';\n"
                       "      } else {\n"
                       "        var statusColor = data.is_online ? 'var(--success)' : 'var(--danger)';\n"
                       "        var statusText = data.is_online ? '✓ 在线' : '✗ 离线';\n"
                       "        var versionBadges = '';\n"
                       "        var hasVersion = false;\n"
                       "        if (data.v1) { versionBadges += '<span class=\"version-badge badge-v1\">v1</span>'; hasVersion = true; }\n"
                       "        if (data.v2) { versionBadges += '<span class=\"version-badge badge-v2\">v2</span>'; hasVersion = true; }\n"
                       "        if (data.v2s) { versionBadges += '<span class=\"version-badge badge-v2s\">v2s</span>'; hasVersion = true; }\n"
                       "        if (data.v3) { versionBadges += '<span class=\"version-badge badge-v3\">v3</span>'; hasVersion = true; }\n"
                       "        if (!hasVersion) { versionBadges = '<span class=\"version-badge badge-unknown\">未知</span>'; }\n"
                       "        resultDiv.innerHTML = '<div style=\"padding:16px;background:var(--card);border:1px solid var(--border);border-radius:8px;\">' +\n"
                       "          '<div style=\"margin-bottom:12px;font-size:16px;\"><strong>主机:</strong> ' + data.host + '</div>' +\n"
                       "          '<div style=\"margin-bottom:12px;\"><strong>状态:</strong> <span style=\"color:' + statusColor + ';font-weight:600;\">' + statusText + '</span></div>' +\n"
                       "          '<div style=\"display:flex;align-items:center;gap:10px;\"><strong>版本:  </strong> ' + versionBadges + '</div>' +\n"
                       "          '</div>';\n"
                       "      }\n"
                       "    })\n"
                       "    .catch(function(err) {\n"
                       "      resultDiv.innerHTML = '<div style=\"color:var(--danger);text-align:center;padding:20px;\">检测失败,请稍后重试</div>';\n"
                       "    });\n"
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
                       "<p>%s</p>\n"
                       "</div>\n"
                       "<div class='stat'>\n"
                       "<h3>最后检测</h3>\n"
                       "<p>%s</p>\n"
                       "</div>\n"
                       "<button id='refreshBtn' onclick='manualRefresh()'\n"
                       "style='padding:8px 16px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent-2));\n"
                       "color:white;border:none;cursor:pointer;font-weight:600;transition:all 0.3s;'> \n"
                       "立即检测</button>\n"
                       "<button id='testMyBtn' onclick='openTestMyModal()'\n"
                       "style='padding:8px 16px;border-radius:8px;background:linear-gradient(135deg,#06b6d4,#7c3aed);\n"
                       "color:white;border:none;cursor:pointer;font-weight:600;transition:all 0.3s;margin-left:8px;'> \n"
                       "测测我的</button>\n"
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
                       interval_str,
                       time_str);
    // 在表格生成循环前添加检查
    if (g_state.host_count == 0)
    {
        len += snprintf(buf + len, bufsize - len,
                        "<tr><td colspan='7' style='text-align:center;padding:40px;color:var(--muted);'>"
                        "暂无配置的主机<br/>"
                        "<small>您可以使用上方的「测测我的」功能检测您的服务器连通性</small>"
                        "</td></tr>\n");
    }
    else
    {
        for (int i = 0; i < g_state.host_count; i++)
        {
            char *history_data = NULL;
            size_t history_data_size = 0;
            // 动态检查剩余空间 (保留 5% 作为安全余量)
            size_t safety_margin = bufsize / 20;
            if ((size_t)len >= bufsize - safety_margin)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [WARN]: 缓冲区接近上限，已生成 %d/%d 个主机\n",
                            timestamp(), i, g_state.host_count);
                }
                break;
            }

            host_stats_t *h = &g_state.hosts[i];
            // 创建安全的主机 ID(将点号替换为连字符)
            char safe_host_id[512];
            strncpy(safe_host_id, h->host, sizeof(safe_host_id) - 1);
            safe_host_id[sizeof(safe_host_id) - 1] = '\0';
            for (char *p = safe_host_id; *p; p++)
            {
                if (*p == '.' || *p == ':' || *p == '/')
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
            char last_check_str[128] = "正在检测";
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
            if (h->history_count > 0)
            {
                // 每条记录约20字节 (时间戳+状态+逗号) + 1KB安全余量
                history_data_size = (h->history_count * 20) + 1024;
                history_data = malloc(history_data_size);

                if (!history_data)
                {
                    // malloc失败时使用较小的fallback缓冲区
                    if (verbose)
                    {
                        fprintf(stderr, "[%s] [WARN]: 无法分配 %zu 字节历史数据缓冲区,使用fallback\n",
                                timestamp(), history_data_size);
                    }
                    history_data_size = 4096;
                    history_data = malloc(history_data_size);
                }

                if (history_data)
                {
                    memset(history_data, 0, history_data_size);

                    // 从最旧的记录开始遍历(循环数组的正确顺序)
                    int start_idx = (h->history_count < h->max_history) ? 0 : h->history_index;
                    for (int j = 0; j < h->history_count; j++)
                    {
                        int idx = (start_idx + j) % h->max_history;
                        char record[64];
                        snprintf(record, sizeof(record), "%ld:%d%s",
                                 h->history[idx].timestamp,
                                 h->history[idx].success,
                                 (j < h->history_count - 1) ? "," : "");

                        // 边界检查,防止 strcat 溢出
                        size_t current_len = strlen(history_data);
                        if (current_len + strlen(record) + 1 < history_data_size)
                        {
                            strcat(history_data, record);
                        }
                        else
                        {
                            if (verbose)
                            {
                                fprintf(stderr, "[%s] [WARN]: %s:%d 历史数据缓冲区已满,已截断\n",
                                        timestamp(), h->host, h->port);
                            }
                            break;
                        }
                    }
                }
            }

            // 如果分配失败,使用空字符串
            if (!history_data)
            {
                history_data = malloc(1);
                if (history_data)
                {
                    history_data[0] = '\0';
                }
                else
                {
                    // 极端情况:连1字节都分配不了,跳过这个主机
                    fprintf(stderr, "[%s] [ERROR]: 无法为 %s:%d 分配任何内存,跳过显示这个主机\n",
                            timestamp(), h->host, h->port);
                    continue; // 跳过这个主机的HTML生成
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
            // 检测是否有特殊前缀
            char display_host[256];
            char display_port[32];
            char copy_text[512];

            const char *display = h->display_name[0] ? h->display_name : h->host;

            if (strncmp(h->host, "txt:", 4) == 0 || strncmp(h->host, "http:", 5) == 0)
            {
                // 显示原始主机名（包含前缀）
                strncpy(display_host, display, sizeof(display_host) - 1);
                display_host[sizeof(display_host) - 1] = '\0';

                // 端口显示为 "" 或实际端口
                if (h->port > 0)
                {
                    snprintf(display_port, sizeof(display_port), "%d", h->port);
                    snprintf(copy_text, sizeof(copy_text), "%s:%d", display_host, h->port);
                }
                else
                {
                    strncpy(display_port, "", sizeof(display_port) - 1);
                    strncpy(copy_text, display_host, sizeof(copy_text) - 1); // 没有端口时不加冒号
                }
            }
            else
            {
                // 普通主机，正常显示
                strncpy(display_host, display, sizeof(display_host) - 1);
                display_host[sizeof(display_host) - 1] = '\0';
                snprintf(display_port, sizeof(display_port), "%d", h->port);
                snprintf(copy_text, sizeof(copy_text), "%s:%d", display_host, h->port);
            }

            len += snprintf(buf + len, bufsize - len,
                            "<tr id='host-%s-%d' data-host='%s' data-port='%d'>"
                            "<td class='host-cell' onclick='copyToClipboard(\"%s\")'>%s</td>"
                            "<td>%s</td>"
                            "<td>%s</td>"
                            "<td onmouseenter='showHistoryTooltip(event, \"%s\")' "
                            "onmouseleave='hideHistoryTooltip()' "
                            "onclick='showHistoryModal(\"%s\", \"%s\", \"%s\")' "
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
                            safe_host_id, h->port, safe_host_id, h->port,
                            copy_text, display_host,
                            display_port,
                            version_badges,
                            history_data,
                            display_host, display_port, history_data,
                            overall_rate_int, // 背景层宽度
                            gradient_bg,      // 动态渐变背景
                            overall_rate_int, // 文字显示
                            status_class, status_text,
                            last_check_str,
                            h->note[0] ? h->note : "✍️");
            free(history_data);
            history_data = NULL;
        }
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

    pthread_rwlock_unlock(&g_state.lock);
}

void update_html_cache(void)
{
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 开始更新 HTML 缓存\n", timestamp());
    }

    // 计算所需缓冲区大小
    pthread_rwlock_rdlock(&g_state.lock);
    size_t base_size = 50000;
    size_t per_host_size = 500 + (g_max_history * 50);
    size_t buffer_size = base_size + (g_state.host_count * per_host_size) + 10000;

    if (buffer_size < 262144)
        buffer_size = 262144;
    if (buffer_size > 10485760)
        buffer_size = 10485760;

    int host_count = g_state.host_count;
    pthread_rwlock_unlock(&g_state.lock);

    // 分配临时缓冲区
    char *temp_buffer = malloc(buffer_size);
    if (!temp_buffer)
    {
        fprintf(stderr, "[%s] [ERROR]: 无法分配 %zu 字节缓存缓冲区\n",
                timestamp(), buffer_size);
        return;
    }

    // 生成 HTML
    generate_html(temp_buffer, buffer_size);
    size_t html_len = strlen(temp_buffer);

    // 更新全局缓存
    pthread_rwlock_wrlock(&g_cache_lock);

    // 释放旧缓存
    if (g_html_cache)
    {
        free(g_html_cache);
    }

    // 设置新缓存
    g_html_cache = temp_buffer;
    g_html_cache_size = html_len;

    pthread_rwlock_unlock(&g_cache_lock);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: HTML 缓存已更新 (%zu 字节, %d 个主机)\n",
                timestamp(), html_len, host_count);
    }
}

// 不区分大小写查找请求头
static char *find_header_value(const char *request, const char *header_name)
{
    const char *p = request;
    size_t header_len = strlen(header_name);

    while (*p)
    {
        // 检查是否匹配请求头名称(不区分大小写)
        int match = 1;
        for (size_t i = 0; i < header_len; i++)
        {
            char c1 = tolower(p[i]);
            char c2 = tolower(header_name[i]);
            if (c1 != c2)
            {
                match = 0;
                break;
            }
        }

        if (match && p[header_len] == ':')
        {
            // 找到匹配的请求头,跳过冒号和空格
            const char *value = p + header_len + 1;
            while (*value == ' ')
                value++;
            return (char *)value;
        }
        p++;
    }
    return NULL;
}

// HTTP 分块传输函数
void send_chunked_response(int client_sock, const char *content, size_t content_len)
{
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 使用分块传输发送 %zu 字节数据\n",
                timestamp(), content_len);
    }

    // 发送 HTTP 头 (使用 chunked 编码)
    const char *header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n";

    send(client_sock, header, strlen(header), 0);

    // 分块大小 (16KB 每块)
    const size_t chunk_size = 16384;
    size_t offset = 0;

    while (offset < content_len)
    {
        size_t remaining = content_len - offset;
        size_t current_chunk = (remaining > chunk_size) ? chunk_size : remaining;

        // 发送块大小 (十六进制格式)
        char chunk_header[32];
        int header_len = snprintf(chunk_header, sizeof(chunk_header), "%zx\r\n", current_chunk);
        send(client_sock, chunk_header, header_len, 0);

        // 发送块数据
        ssize_t sent = send(client_sock, content + offset, current_chunk, 0);
        if (sent <= 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [ERROR]: 分块传输失败: %s\n",
                        timestamp(), strerror(errno));
            }
            break;
        }

        // 发送块结束标记
        send(client_sock, "\r\n", 2, 0);

        offset += current_chunk;

        if (verbose && offset % (chunk_size * 10) == 0)
        {
            fprintf(stderr, "[%s] [DEBUG]: 已发送 %zu/%zu 字节 (%.1f%%)\n",
                    timestamp(), offset, content_len,
                    (offset * 100.0) / content_len);
        }
    }

    // 发送结束块 (大小为 0)
    send(client_sock, "0\r\n\r\n", 5, 0);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 分块传输完成，共发送 %zu 字节\n",
                timestamp(), offset);
    }
}

void send_compressed_response(int client_sock, const char *content, size_t content_len)
{
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 开始压缩 %zu 字节数据\n",
                timestamp(), content_len);
    }

    // 计算压缩后的最大大小
    uLongf compressed_size = compressBound(content_len);
    unsigned char *compressed = malloc(compressed_size);

    if (!compressed)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [ERROR]: 压缩缓冲区分配失败，使用未压缩传输\n", timestamp());
        }
        send_chunked_response(client_sock, content, content_len);
        return;
    }

    // 执行 gzip 压缩
    int result = compress2(compressed, &compressed_size,
                           (const unsigned char *)content, content_len,
                           Z_DEFAULT_COMPRESSION);

    if (result != Z_OK)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [ERROR]: 压缩失败 (错误码: %d)，使用未压缩传输\n",
                    timestamp(), result);
        }
        free(compressed);
        send_chunked_response(client_sock, content, content_len);
        return;
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 压缩完成: %zu -> %lu 字节 (压缩率: %.1f%%)\n",
                timestamp(), content_len, compressed_size,
                (compressed_size * 100.0) / content_len);
    }

    // 发送 HTTP 头（带 gzip 编码）
    const char *header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Encoding: deflate\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n";

    send(client_sock, header, strlen(header), 0);

    // 分块发送压缩数据
    const size_t chunk_size = 16384;
    size_t offset = 0;

    while (offset < compressed_size)
    {
        size_t remaining = compressed_size - offset;
        size_t current_chunk = (remaining > chunk_size) ? chunk_size : remaining;

        // 发送块大小（十六进制格式）
        char chunk_header[32];
        int header_len = snprintf(chunk_header, sizeof(chunk_header), "%zx\r\n", current_chunk);
        send(client_sock, chunk_header, header_len, 0);

        // 发送块数据
        ssize_t sent = send(client_sock, compressed + offset, current_chunk, 0);
        if (sent <= 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [ERROR]: 压缩数据传输失败: %s\n",
                        timestamp(), strerror(errno));
            }
            break;
        }

        // 发送块结束标记
        send(client_sock, "\r\n", 2, 0);

        offset += current_chunk;
    }

    // 发送结束块
    send(client_sock, "0\r\n\r\n", 5, 0);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 压缩数据传输完成，共发送 %zu 字节\n",
                timestamp(), offset);
    }

    free(compressed);
}

void generate_svg_response(int client_sock, int is_online, float uptime,
                           int v1_ok, int v2_ok, int v2s_ok, int v3_ok)
{
    if (verbose)
    {
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
    if (version_count > 0)
    {
        version_value_width = version_count * 22 + (version_count - 1) * 2;
    }
    else
    {
        version_value_width = 28;
    }

    int badge_gap = 1; // 徽章之间的间距
    int status_total = status_label_width + status_value_width + 16;
    int uptime_total = uptime >= 0 ? (uptime_label_width + uptime_value_width + 16) : 0;
    int version_total = version_label_width + version_value_width + 16;
    int total_width = status_total + (uptime_total > 0 ? uptime_total + badge_gap : 0) + version_total + badge_gap;

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: SVG 尺寸: status=%d, uptime=%d, version=%d, total=%d\n",
                timestamp(), status_total, uptime_total, version_total, total_width);
    }

    // SVG 内容
    len += snprintf(svg + len, sizeof(svg) - len,
                    "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"20\">\n",
                    total_width);

    // 状态徽章（独立，左右圆角）
    const char *status_color = is_online ? "#4ade80" : "#ef4444";

    if (verbose)
    {
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
    if (uptime >= 0)
    {
        int hue = 10 + (int)(uptime * 0.8);
        char uptime_color[32];
        snprintf(uptime_color, sizeof(uptime_color), "hsl(%d, 90%%, 50%%)", hue);

        if (verbose)
        {
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
    if (is_online)
    {
        // ========== 版本徽章（独立，左右圆角）==========
        int version_start = status_total + (uptime_total > 0 ? uptime_total + badge_gap : 0) + badge_gap;
        int version_mid = version_start + version_label_width + 8;
        int version_end = version_start + version_total;

        if (verbose)
        {
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
        if (version_count == 1)
        {
            // 只检测到一个版本，使用对应颜色
            if (v1_ok)
            {
                version_bg_color = "#7c3aed"; // v1 紫色
            }
            else if (v2_ok)
            {
                version_bg_color = "#0284c7"; // v2 深蓝色
            }
            else if (v2s_ok)
            {
                version_bg_color = "#0369a1"; // v2s 中蓝色
            }
            else
            {                                 // v3_ok
                version_bg_color = "#d97706"; // v3 橙色
            }
        }
        else if (version_count > 1)
        {
            // 检测到多个版本，使用红色
            version_bg_color = "#ef4444";
        }
        else
        {
            // 未检测到任何版本，使用红色
            version_bg_color = "#ef4444";
        }

        // 版本徽章 - 右侧部分（左边直角，右边圆角）- 使用动态背景颜色
        int version_right = version_end - 5;
        len += snprintf(svg + len, sizeof(svg) - len,
                        "  <path d=\"M %d 0 L %d 0 Q %d 0 %d 3 L %d 17 Q %d 20 %d 20 L %d 20 L %d 0 Z\" fill=\"%s\"/>\n",
                        version_mid, version_right, version_end, version_end,
                        version_end, version_end, version_right, version_mid, version_mid,
                        version_bg_color); // 使用动态颜色

        // 版本徽章文字
        int version_label_center = version_start + (version_mid - version_start) / 2;
        len += snprintf(svg + len, sizeof(svg) - len,
                        "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">版本</text>\n",
                        version_label_center);

        // 生成版本标签
        if (version_count > 0)
        {
            int x_offset = version_mid + 4;

            if (v1_ok)
            {
                len += snprintf(svg + len, sizeof(svg) - len,
                                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v1</text>\n",
                                x_offset + 5);
                x_offset += 24;
            }

            if (v2_ok)
            {
                len += snprintf(svg + len, sizeof(svg) - len,
                                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v2</text>\n",
                                x_offset + 5);
                x_offset += 24;
            }

            if (v2s_ok)
            {
                // v2s: 中蓝色背景 #0369a1
                len += snprintf(svg + len, sizeof(svg) - len,
                                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v2s</text>\n",
                                x_offset + 6);
                x_offset += 28;
            }

            if (v3_ok)
            {
                // v3: 橙色背景 #d97706
                len += snprintf(svg + len, sizeof(svg) - len,
                                "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"10\" font-weight=\"600\">v3</text>\n",
                                x_offset + 5);
            }
        }
        else
        {
            // 未知版本：使用红色背景 #ef4444
            int version_value_center = version_mid + (version_value_width + 8) / 2;
            len += snprintf(svg + len, sizeof(svg) - len,
                            "  <text x=\"%d\" y=\"14\" fill=\"#fff\" font-size=\"11\" text-anchor=\"middle\">未知</text>\n",
                            version_value_center);
        }
    }
    len += snprintf(svg + len, sizeof(svg) - len, "</svg>\n");

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: SVG 生成完成，总长度: %d 字节\n", timestamp(), len);
    }

    // 对于小响应，直接发送；大响应使用分块传输
    if (len < 4096)
    {
        send(client_sock, svg, len, 0);
    }
    else
    {
        send_chunked_response(client_sock, svg, len);
    }
    close(client_sock);
}

void send_error_response(int client_sock, const char *message)
{
    char response[512];
    int len = snprintf(response, sizeof(response),
                       "HTTP/1.1 400 Bad Request\r\n"
                       "Content-Type: text/plain; charset=utf-8\r\n"
                       "Connection: close\r\n\r\n"
                       "%s",
                       message);
    send(client_sock, response, len, 0);
    close(client_sock);
}
void handle_api_request(int client_sock, const char *path)
{
    // 提取 supernode 参数
    char *query = strchr(path, '?');
    if (!query)
    {
        close(client_sock);
        return;
    }

    char supernode[512] = {0};
    char *param = strstr(query, "supernode=");
    if (!param)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: API请求缺少查询参数\n", timestamp());
        }
        close(client_sock);
        return;
    }

    // 解析参数值
    sscanf(param + 10, "%511[^&]", supernode);
    if (strlen(supernode) == 0)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: API请求 supernode 参数为空\n", timestamp());
        }
        close(client_sock);
        return;
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: API请求解析到 supernode 参数: %s\n", timestamp(), supernode);
    }

    // 先检测特殊前缀
    int has_special_prefix = 0;
    if (strncmp(supernode, "txt:", 4) == 0 || strncmp(supernode, "http:", 5) == 0)
    {
        has_special_prefix = 1;
    }
    // 尝试分离端口号
    char query_name[256] = {0};
    int user_port = 0; // 用户提供的端口

    if (has_special_prefix)
    {
        // 对于特殊前缀,跳过前缀后再查找冒号
        const char *host_part = (strncmp(supernode, "txt:", 4) == 0) ? supernode + 4 : supernode + 5;

        // 对于 http: 前缀,需要先查找路径分隔符
        if (strncmp(supernode, "http:", 5) == 0)
        {
            char *slash = strchr(host_part, '/');

            if (slash)
            {
                // 有路径,在路径之前查找端口
                char temp_host[256];
                size_t host_len = slash - host_part;
                strncpy(temp_host, host_part, host_len);
                temp_host[host_len] = '\0';

                char *temp_colon = strchr(temp_host, ':');
                if (temp_colon)
                {
                    // 提取主机名和端口
                    size_t prefix_len = host_part - supernode;
                    size_t name_len = prefix_len + (temp_colon - temp_host);
                    strncpy(query_name, supernode, name_len);
                    query_name[name_len] = '\0';

                    // 对于带路径的 http: 前缀，端口应该设为 0 以匹配配置文件
                    user_port = 0; // 修改这里，不再提取端口
                }
                else
                {
                    // 没有端口,只有路径
                    strncpy(query_name, supernode, sizeof(query_name) - 1);
                    user_port = 0;
                }
            }
            else
            {
                // 没有路径,正常处理
                char *colon = strchr(host_part, ':');
                if (colon)
                {
                    size_t prefix_len = host_part - supernode;
                    size_t name_len = prefix_len + (colon - host_part);
                    strncpy(query_name, supernode, name_len);
                    query_name[name_len] = '\0';
                    user_port = atoi(colon + 1);
                }
                else
                {
                    strncpy(query_name, supernode, sizeof(query_name) - 1);
                    user_port = 0;
                }
            }
        }
        else
        {
            // txt: 前缀,原有逻辑
            char *colon = strchr(host_part, ':');
            if (colon)
            {
                size_t prefix_len = host_part - supernode;
                size_t name_len = prefix_len + (colon - host_part);
                strncpy(query_name, supernode, name_len);
                query_name[name_len] = '\0';
                user_port = atoi(colon + 1);
            }
            else
            {
                strncpy(query_name, supernode, sizeof(query_name) - 1);
                user_port = 0;
            }
        }
    }

    // 尝试匹配前端显示名称
    char actual_host[256] = {0};
    int actual_port = 0;
    int found = 0;

    pthread_rwlock_wrlock(&g_state.lock);
    for (int i = 0; i < g_state.host_count; i++)
    {
        if (g_state.hosts[i].display_name[0] &&
            strcmp(g_state.hosts[i].display_name, query_name) == 0)
        {
            strncpy(actual_host, g_state.hosts[i].host, sizeof(actual_host) - 1);
            // 关键修改: 如果用户提供了端口,使用用户端口;否则使用配置文件端口
            if (user_port > 0 && user_port <= 65535)
            {
                actual_port = user_port;
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: API请求匹配到前端显示名称 '%s' -> %s:%d (使用用户提供的端口)\n",
                            timestamp(), query_name, actual_host, actual_port);
                }
            }
            else
            {
                actual_port = g_state.hosts[i].port;
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: API请求匹配到前端显示名称 '%s' -> %s:%d (使用配置文件端口)\n",
                            timestamp(), query_name, actual_host, actual_port);
                }
            }
            found = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&g_state.lock);

    // 如果未找到匹配的前端显示名称,按原格式解析 host:port
    if (!found)
    {
        // 检查是否有特殊前缀
        if (strncmp(supernode, "txt:", 4) == 0 || strncmp(supernode, "http:", 5) == 0)
        {
            // 特殊前缀，直接使用 supernode 作为 actual_host
            strncpy(actual_host, supernode, sizeof(actual_host) - 1);
            actual_host[sizeof(actual_host) - 1] = '\0';

            // 对于 http: 前缀，检查是否有路径
            if (strncmp(supernode, "http:", 5) == 0)
            {
                const char *host_part = supernode + 5;
                char *slash = strchr(host_part, '/');

                if (slash)
                {
                    // 有路径，端口设为 0（与配置文件解析逻辑一致）
                    actual_port = 0;
                }
                else
                {
                    // 没有路径，正常提取端口
                    char *colon = strchr(host_part, ':');
                    if (colon)
                    {
                        actual_port = atoi(colon + 1);
                    }
                    else
                    {
                        actual_port = 0;
                    }
                }
            }
            else
            {
                // txt: 前缀，正常提取端口
                const char *host_part = supernode + 4;
                char *colon = strchr(host_part, ':');
                if (colon)
                {
                    actual_port = atoi(colon + 1);
                }
                else
                {
                    actual_port = 0;
                }
            }
        }
        else
        {
            // 普通主机，必须有有效端口
            if (sscanf(supernode, "%255[^:]:%d", actual_host, &actual_port) != 2 ||
                actual_port <= 0 || actual_port > 65535)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: API请求 supernode 参数值格式错误: %s\n",
                            timestamp(), supernode);
                }
                send_error_response(client_sock, "格式错误,正确格式: host:port 或前端显示主机名[:port]");
                return;
            }
        }
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: API请求解析为 host:port 格式: %s:%d\n",
                    timestamp(), actual_host, actual_port);
        }
    }
    // 解析真实的 IP 和端口
    char real_host[256];
    int real_port;

    // 检查是否有特殊前缀
    if (strncmp(actual_host, "txt:", 4) == 0)
    {
        // TXT 记录解析
        if (resolve_txt_record(actual_host, real_host, &real_port) != 0)
        {
            // 解析失败
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: API请求 TXT 解析失败: %s\n",
                        timestamp(), actual_host);
            }
            send_error_response(client_sock, "✗ TXT解析失败");
            return;
        }
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: API请求 TXT 解析: %s -> %s:%d\n",
                    timestamp(), actual_host, real_host, real_port);
        }
    }
    else if (strncmp(actual_host, "http:", 5) == 0)
    {
        // HTTP 重定向解析
        if (resolve_http_redirect(actual_host, actual_port, real_host, &real_port) != 0)
        {
            // 解析失败
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: API请求 HTTP 解析失败: %s\n",
                        timestamp(), actual_host);
            }
            send_error_response(client_sock, "✗ HTTP解析失败");
            return;
        }
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: API请求 HTTP 解析: %s -> %s:%d\n",
                    timestamp(), actual_host, real_host, real_port);
        }
    }
    else
    {
        // 普通主机，直接使用
        strncpy(real_host, actual_host, sizeof(real_host) - 1);
        real_host[sizeof(real_host) - 1] = '\0';
        real_port = actual_port;
    }
    // 执行检测
    int v1_ok = 0, v2_ok = 0, v2s_ok = 0, v3_ok = 0;
    int result = test_supernode_internal(real_host, real_port, &v1_ok, &v2_ok, &v2s_ok, &v3_ok);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: API请求 %s:%d 检测结果: result=%d, v1=%d, v2=%d, v2s=%d, v3=%d\n",
                timestamp(), actual_host, actual_port, result, v1_ok, v2_ok, v2s_ok, v3_ok);
    }

    // 检查历史记录
    float uptime = -1.0f;
    pthread_rwlock_wrlock(&g_state.lock);
    for (int i = 0; i < g_state.host_count; i++)
    {
        if (strcmp(g_state.hosts[i].host, actual_host) == 0 &&
            g_state.hosts[i].port == actual_port)
        {
            uptime = calculate_uptime(&g_state.hosts[i]);
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: API请求 %s:%d 找到历史记录: uptime=%.2f%%\n", timestamp(), actual_host, actual_port, uptime);
            }
            break;
        }
    }
    pthread_rwlock_unlock(&g_state.lock);

    // 生成 SVG 响应
    generate_svg_response(client_sock, result == 0, uptime, v1_ok, v2_ok, v2s_ok, v3_ok);
}

static void call_status_change_script(host_stats_t *h, int is_online,
                                      int v1_ok, int v2_ok, int v2s_ok, int v3_ok)
{
    // 检查脚本是否存在且有执行权限
    if (access(g_callback_script, X_OK) != 0)
    {
        fprintf(stderr, "[%s] [ERROR]: %s 状态变化，脚本 %s 不存在或无执行权限: %s\n",
                timestamp(), h->host, g_callback_script, strerror(errno));
        return;
    }
    // 构建版本字符串,防止为空
    char versions[64] = "";
    int has_version = 0;
    if (v1_ok)
    {
        strcat(versions, "v1 ");
        has_version = 1;
    }
    if (v2_ok)
    {
        strcat(versions, "v2 ");
        has_version = 1;
    }
    if (v2s_ok)
    {
        strcat(versions, "v2s ");
        has_version = 1;
    }
    if (v3_ok)
    {
        strcat(versions, "v3 ");
        has_version = 1;
    }

    // 如果没有检测到任何版本,使用占位符
    if (!has_version)
    {
        strcpy(versions, "Unknown");
    }

    // 构建主机标识 - 使用真实主机名(h->host),不使用隐私名(display_name)
    char host_id[512];
    if (h->port > 0)
        snprintf(host_id, sizeof(host_id), "%s:%d", h->host, h->port);
    else
        snprintf(host_id, sizeof(host_id), "%s", h->host);

    // 构建命令
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "%s \"%s\" \"%s\" \"%s\"",
             g_callback_script, host_id, versions, is_online ? "up" : "down");

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: %s 状态变化，调用脚本: %s\n", timestamp(), host_id, cmd);
    }

    // 双重 fork 避免僵尸进程
    pid_t pid = fork();
    if (pid == 0)
    {
        // 第一个子进程立即再 fork
        if (fork() == 0)
        {
            // 孙进程执行脚本,先尝试 /bin/sh
            execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
            // 如果 /bin/sh 失败,尝试 /bin/bash
            execl("/bin/bash", "bash", "-c", cmd, (char *)NULL);
            // 如果都失败,退出子进程
            exit(1);
        }
        // 第一个子进程立即退出
        exit(0);
    }
    else if (pid > 0)
    {
        // 父进程等待第一个子进程(很快就会退出)
        waitpid(pid, NULL, 0);
    }
    else
    {
        // fork 失败
        // if (verbose)
        // {
        fprintf(stderr, "[%s] [ERROR]: %s 状态变化，调用脚本时 fork() 失败: %s 无法执行\n", timestamp(), host_id, strerror(errno));
        // }
    }
}

// 并行检测工作线程
void *check_host_worker(void *arg)
{
    check_task_t *task = (check_task_t *)arg;

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 工作线程开始检测 %s:%d\n",
                timestamp(), task->host, task->port);
    }

    // 解析真实的 IP 和端口
    char real_host[256];
    int real_port;
    int resolve_failed = 0;

    if (strncmp(task->host, "txt:", 4) == 0)
    {
        // TXT 记录解析
        if (resolve_txt_record(task->host, real_host, &real_port) == 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: TXT 解析: %s -> %s:%d\n",
                        timestamp(), task->host, real_host, real_port);
            }
        }
        else
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: TXT 解析失败: %s\n",
                        timestamp(), task->host);
            }
            resolve_failed = 1;
        }
    }
    else if (strncmp(task->host, "http:", 5) == 0)
    {
        // HTTP 重定向解析
        if (resolve_http_redirect(task->host, task->port, real_host, &real_port) == 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: HTTP 解析: %s -> %s:%d\n",
                        timestamp(), task->host, real_host, real_port);
            }
        }
        else
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: HTTP 解析失败: %s\n",
                        timestamp(), task->host);
            }
            resolve_failed = 1;
        }
    }
    else
    {
        // 普通主机，直接使用原始地址
        strncpy(real_host, task->host, sizeof(real_host) - 1);
        real_host[sizeof(real_host) - 1] = '\0';
        real_port = task->port;
    }

    // 执行检测
    if (!resolve_failed)
    {
        test_supernode_internal(real_host, real_port,
                                &task->v1_ok, &task->v2_ok,
                                &task->v2s_ok, &task->v3_ok);
    }
    else
    {
        // 解析失败，所有版本标记为失败
        task->v1_ok = 0;
        task->v2_ok = 0;
        task->v2s_ok = 0;
        task->v3_ok = 0;
    }

    // 判断是否在线
    task->is_online = (task->v1_ok || task->v2_ok || task->v2s_ok || task->v3_ok);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 工作线程完成检测 %s:%d - %s (v1:%s v2:%s v2s:%s v3:%s)\n",
                timestamp(), task->host, task->port,
                task->is_online ? "在线" : "离线",
                task->v1_ok ? "✓" : "✗",
                task->v2_ok ? "✓" : "✗",
                task->v2s_ok ? "✓" : "✗",
                task->v3_ok ? "✓" : "✗");
    }

    return NULL;
}

// 处理手动刷新请求（使用并行检测）
void handle_refresh_request(int client_sock)
{
    time_t now = time(NULL);
    pthread_rwlock_rdlock(&g_state.lock);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 收到刷新请求 - now=%ld, last_manual_refresh=%ld, 间隔=%d秒, 差值=%ld秒\n",
                timestamp(), now, last_manual_refresh, manual_refresh_interval * 60, now - last_manual_refresh);
    }

    // 检查刷新间隔
    if (now - last_manual_refresh < manual_refresh_interval * 60)
    {
        pthread_rwlock_unlock(&g_state.lock);

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 刷新间隔未到,拒绝请求\n", timestamp());
        }

        char response[512];
        int len = snprintf(response, sizeof(response),
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json; charset=utf-8\r\n"
                           "Connection: close\r\n\r\n"
                           "{\"success\":false,\"message\":\"哎呀，才刚刚检测过呢,等等再试哦~\"}");
        send(client_sock, response, len, 0);
        close(client_sock);
        return;
    }

    last_manual_refresh = now;
    int total_hosts = g_state.host_count;
    pthread_rwlock_unlock(&g_state.lock);

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 开始执行刷新,检测 %d 个主机\n", timestamp(), total_hosts);
    }

    // 检查配置文件是否被修改
    if (g_state.config_file_path[0] != '\0')
    {
        struct stat st;
        if (stat(g_state.config_file_path, &st) == 0)
        {
            if (st.st_mtime > g_state.config_mtime)
            {
                // 转换旧时间
                struct tm *old_tm = localtime(&g_state.config_mtime);
                char old_time_str[64];
                strftime(old_time_str, sizeof(old_time_str), "%Y年%m月%d日 %H时%M分%S秒", old_tm);

                // 转换新时间
                struct tm *new_tm = localtime(&st.st_mtime);
                char new_time_str[64];
                strftime(new_time_str, sizeof(new_time_str), "%Y年%m月%d日 %H时%M分%S秒", new_tm);

                fprintf(stderr, "[%s] [DEBUG]: 配置文件已修改 (上次是%s, 当前为%s)重新加载\n",
                        timestamp(), old_time_str, new_time_str);

                g_state.config_mtime = st.st_mtime;
                reload_config();
            }
        }
        else if (verbose)
        {
            fprintf(stderr, "[%s] [WARN]: 无法访问配置文件: %s\n",
                    timestamp(), strerror(errno));
        }
    }

    if (total_hosts > 0)
    {
        // ========== 并行检测逻辑 ==========
        for (int i = 0; i < total_hosts; i += g_max_parallel_checks)
        {
            // 计算本批次要检测的主机数量
            int batch_size = (i + g_max_parallel_checks > total_hosts)
                                 ? (total_hosts - i)
                                 : g_max_parallel_checks;

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 手动刷新批次 %d/%d，检测 %d 个主机\n",
                        timestamp(), i / g_max_parallel_checks + 1,
                        (total_hosts + g_max_parallel_checks - 1) / g_max_parallel_checks,
                        batch_size);
            }

            // 准备任务和线程数组
            check_task_t tasks[g_max_parallel_checks];
            pthread_t threads[g_max_parallel_checks];

            // 启动一批检测线程
            for (int j = 0; j < batch_size; j++)
            {
                int idx = i + j;

                // 从全局状态复制主机信息
                pthread_rwlock_rdlock(&g_state.lock);
                memset(&tasks[j], 0, sizeof(check_task_t));
                strncpy(tasks[j].host, g_state.hosts[idx].host, sizeof(tasks[j].host) - 1);
                tasks[j].host[sizeof(tasks[j].host) - 1] = '\0';
                tasks[j].port = g_state.hosts[idx].port;
                pthread_rwlock_unlock(&g_state.lock);

                tasks[j].host_index = idx;

                // 创建线程
                if (pthread_create(&threads[j], NULL, check_host_worker, &tasks[j]) != 0)
                {
                    fprintf(stderr, "[%s] [ERROR]: 无法创建检测线程 %d: %s\n",
                            timestamp(), j, strerror(errno));
                    // 如果线程创建失败，直接在主线程中执行
                    check_host_worker(&tasks[j]);
                }
            }

            // 等待所有线程完成
            for (int j = 0; j < batch_size; j++)
            {
                pthread_join(threads[j], NULL);
            }

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 批次完成，开始更新统计数据\n", timestamp());
            }

            // 批量更新统计数据（一次性加写锁）
            pthread_rwlock_wrlock(&g_state.lock);

            for (int j = 0; j < batch_size; j++)
            {
                int idx = tasks[j].host_index;
                host_stats_t *h = &g_state.hosts[idx];

                // 更新统计
                h->total_checks++;
                if (tasks[j].v1_ok)
                    h->success_v1++;
                if (tasks[j].v2_ok)
                    h->success_v2++;
                if (tasks[j].v2s_ok)
                    h->success_v2s++;
                if (tasks[j].v3_ok)
                    h->success_v3++;
                h->last_check = time(NULL);

                // 检测状态变化
                if (g_callback_script[0] != '\0' && h->last_online_status != tasks[j].is_online)
                {
                    // 避免首次检测时就是在线的情况触发
                    if (h->last_online_status != -1 || !tasks[j].is_online)
                    {
                        call_status_change_script(h, tasks[j].is_online,
                                                  tasks[j].v1_ok, tasks[j].v2_ok,
                                                  tasks[j].v2s_ok, tasks[j].v3_ok);
                    }
                }
                h->last_online_status = tasks[j].is_online;

                // 添加检测记录到历史数组
                add_check_record(h, tasks[j].is_online);

                // 更新状态文本
                snprintf(h->last_status, sizeof(h->last_status),
                         tasks[j].is_online ? "✓ 在线" : "✗ 离线");

                // 保存历史记录到文件
                save_history(h);

                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测结果: %s (v1:%s v2:%s v2s:%s v3:%s)\n",
                            timestamp(), h->host, h->port,
                            tasks[j].is_online ? "在线" : "离线",
                            tasks[j].v1_ok ? "✓" : "✗",
                            tasks[j].v2_ok ? "✓" : "✗",
                            tasks[j].v2s_ok ? "✓" : "✗",
                            tasks[j].v3_ok ? "✓" : "✗");
                }
            }

            pthread_rwlock_unlock(&g_state.lock);
            // 更新 HTML 缓存
            update_html_cache();
        }

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 刷新完成,发送成功响应\n", timestamp());
        }
    }
    else
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 没有配置主机,跳过本轮检测\n", timestamp());
        }
    }

    // 所有检测完成后才发送响应
    char response[512];
    int len = snprintf(response, sizeof(response),
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json; charset=utf-8\r\n"
                       "Connection: close\r\n\r\n"
                       "{\"success\":true,\"message\":\"刷新成功\"}");
    send(client_sock, response, len, 0);
    close(client_sock);
}

void send_json_response(int client_sock, const char *json)
{
    char response[2048];
    int len = snprintf(response, sizeof(response),
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: application/json; charset=utf-8\r\n"
                       "Connection: close\r\n\r\n%s",
                       json);
    send(client_sock, response, len, 0);
    close(client_sock);
}

// 处理 /testmy 请求
void handle_testmy_request(int client_sock, const char *path)
{
    char address[512] = {0};
    char *param = strstr(path, "address=");
    if (!param)
    {
        send_json_response(client_sock, "{\"error\":\"缺少address参数\"}");
        return;
    }

    // URL解码并提取地址
    sscanf(param + 8, "%511[^&]", address);

    // URL解码(处理%3A为:等)
    char decoded[512];
    int j = 0;
    for (int i = 0; address[i] && j < 511; i++)
    {
        if (address[i] == '%' && address[i + 1] && address[i + 2])
        {
            char hex[3] = {address[i + 1], address[i + 2], 0};
            decoded[j++] = (char)strtol(hex, NULL, 16);
            i += 2;
        }
        else
        {
            decoded[j++] = address[i];
        }
    }
    decoded[j] = '\0';

    // 【防止命令注入】检查是否包含危险字符
    for (int i = 0; decoded[i]; i++)
    {
        char c = decoded[i];
        // 只允许: 字母、数字、点、冒号、斜杠、连字符
        if (!isalnum(c) && c != '.' && c != ':' && c != '/' && c != '-' && c != '_')
        {
            send_json_response(client_sock, "{\"error\":\"输入包含非法字符\"}");
            return;
        }
    }

    // 解析主机和端口(支持特殊前缀)
    char host[256] = {0};
    int port = 0;

    // 检查特殊前缀
    if (strncmp(decoded, "txt:", 4) == 0)
    {
        const char *host_part = decoded + 4;
        char *colon = strchr(host_part, ':');
        if (colon)
        {
            size_t host_len = colon - host_part;
            if (host_len >= sizeof(host))
                host_len = sizeof(host) - 1;
            strncpy(host, decoded, 4 + host_len);
            host[4 + host_len] = '\0';
            port = atoi(colon + 1);
        }
        else
        {
            // 没有端口,使用完整地址
            strncpy(host, decoded, sizeof(host) - 1);
            port = 0;
        }
    }
    else if (strncmp(decoded, "http:", 5) == 0)
    {
        const char *host_part = decoded + 5;
        char *slash = strchr(host_part, '/');

        if (slash)
        {
            // 有路径,端口为0
            strncpy(host, decoded, sizeof(host) - 1);
            port = 0;
        }
        else
        {
            char *colon = strchr(host_part, ':');
            if (colon)
            {
                size_t host_len = colon - host_part;
                if (host_len >= sizeof(host))
                    host_len = sizeof(host) - 1;
                strncpy(host, decoded, 5 + host_len);
                host[5 + host_len] = '\0';
                port = atoi(colon + 1);
            }
            else
            {
                strncpy(host, decoded, sizeof(host) - 1);
                port = 0;
            }
        }
    }
    else
    {
        // 普通主机,必须有端口
        if (sscanf(decoded, "%255[^:]:%d", host, &port) != 2 || port <= 0)
        {
            send_json_response(client_sock, "{\"error\":\"格式错误\"}");
            return;
        }
    }

    // 【检查是否是已配置的主机或隐私主机名】
    int is_mine = 0;
    pthread_rwlock_wrlock(&g_state.lock);

    // 去除用户输入的所有空格和换行符
    char cleaned_decoded[512] = {0};
    int k = 0;
    for (int i = 0; decoded[i] != '\0' && k < 511; i++)
    {
        if (decoded[i] != ' ' && decoded[i] != '\t' && decoded[i] != '\n' && decoded[i] != '\r')
        {
            cleaned_decoded[k++] = decoded[i];
        }
    }
    cleaned_decoded[k] = '\0';

    // 去除解析后主机名的所有空格和换行符
    char cleaned_host[256] = {0};
    k = 0;
    for (int i = 0; host[i] != '\0' && k < 255; i++)
    {
        if (host[i] != ' ' && host[i] != '\t' && host[i] != '\n' && host[i] != '\r')
        {
            cleaned_host[k++] = host[i];
        }
    }
    cleaned_host[k] = '\0';

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 测测我的 - 用户输入的主机: %s (格式化后: %s)\n",
                timestamp(), decoded, cleaned_decoded);
        fprintf(stderr, "[%s] [DEBUG]: 测测我的 - 本地已配置的主机: %s (格式化后: %s), 端口: %d\n",
                timestamp(), host, cleaned_host, port);
    }

    for (int i = 0; i < g_state.host_count; i++)
    {
        // 去除配置中主机名的所有空格和换行符
        char cleaned_config_host[256] = {0};
        k = 0;
        for (int j = 0; g_state.hosts[i].host[j] != '\0' && k < 255; j++)
        {
            if (g_state.hosts[i].host[j] != ' ' && g_state.hosts[i].host[j] != '\t' &&
                g_state.hosts[i].host[j] != '\n' && g_state.hosts[i].host[j] != '\r')
            {
                cleaned_config_host[k++] = g_state.hosts[i].host[j];
            }
        }
        cleaned_config_host[k] = '\0';

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 测测我的 - 检查配置[%d]: host=%s (清理后: %s), port=%d, display_name=%s\n",
                    timestamp(), i, g_state.hosts[i].host, cleaned_config_host,
                    g_state.hosts[i].port, g_state.hosts[i].display_name);
        }

        // 检查真实主机名和端口
        if (strcmp(cleaned_config_host, cleaned_host) == 0 &&
            g_state.hosts[i].port == port)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 测测我的 - 匹配到真实主机名: %s:%d\n",
                        timestamp(), cleaned_host, port);
            }
            is_mine = 1;
            break;
        }

        // 检查隐私主机名(display_name:port)
        if (g_state.hosts[i].display_name[0] != '\0')
        {
            // 去除 display_name 的所有空格和换行符
            char cleaned_display[256] = {0};
            k = 0;
            for (int j = 0; g_state.hosts[i].display_name[j] != '\0' && k < 255; j++)
            {
                if (g_state.hosts[i].display_name[j] != ' ' && g_state.hosts[i].display_name[j] != '\t' &&
                    g_state.hosts[i].display_name[j] != '\n' && g_state.hosts[i].display_name[j] != '\r')
                {
                    cleaned_display[k++] = g_state.hosts[i].display_name[j];
                }
            }
            cleaned_display[k] = '\0';

            char display_with_port[512];
            if (g_state.hosts[i].port > 0)
            {
                snprintf(display_with_port, sizeof(display_with_port), "%s:%d",
                         cleaned_display, g_state.hosts[i].port);
            }
            else
            {
                strncpy(display_with_port, cleaned_display, sizeof(display_with_port) - 1);
                display_with_port[sizeof(display_with_port) - 1] = '\0';
            }

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 测测我的 - 拼接隐私主机名: '%s', 比较对象: '%s'\n",
                        timestamp(), display_with_port, cleaned_decoded);
            }

            if (strcmp(display_with_port, cleaned_decoded) == 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 测测我的 - 匹配到隐私主机名: %s\n",
                            timestamp(), display_with_port);
                }
                is_mine = 1;
                break;
            }
        }
    }

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 测测我的 - 检查结果: is_mine=%d\n", timestamp(), is_mine);
    }
    pthread_rwlock_unlock(&g_state.lock);

    if (is_mine)
    {
        send_json_response(client_sock, "{\"is_mine\":true}");
        return;
    }

    // 解析真实IP和端口(处理txt:/http:前缀)
    char real_host[256];
    int real_port;

    if (strncmp(host, "txt:", 4) == 0)
    {
        if (resolve_txt_record(host, real_host, &real_port) != 0)
        {
            send_json_response(client_sock, "{\"error\":\"TXT解析失败\"}");
            return;
        }
    }
    else if (strncmp(host, "http:", 5) == 0)
    {
        if (resolve_http_redirect(host, port, real_host, &real_port) != 0)
        {
            send_json_response(client_sock, "{\"error\":\"HTTP解析失败\"}");
            return;
        }
    }
    else
    {
        strncpy(real_host, host, sizeof(real_host) - 1);
        real_host[sizeof(real_host) - 1] = '\0';
        real_port = port;
    }

    // 执行检测
    int v1_ok = 0, v2_ok = 0, v2s_ok = 0, v3_ok = 0;
    int result = test_supernode_internal(real_host, real_port, &v1_ok, &v2_ok, &v2s_ok, &v3_ok);

    // 返回结果时使用原始输入作为显示
    char response[1024];
    snprintf(response, sizeof(response),
             "{\"is_mine\":false,\"is_online\":%s,\"host\":\"%s\",\"v1\":%d,\"v2\":%d,\"v2s\":%d,\"v3\":%d}",
             (result == 0) ? "true" : "false", decoded, v1_ok, v2_ok, v2s_ok, v3_ok);
    send_json_response(client_sock, response);
}

// HTTP 请求处理
void handle_http_request(int client_sock)
{
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 开始处理 HTTP 请求 (socket fd=%d)\n", timestamp(), client_sock);
    }
    char request[2048];
    ssize_t n = recv(client_sock, request, sizeof(request) - 1, 0);
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 接收到 %zd 字节请求数据\n", timestamp(), n);
    }

    if (n > 0)
    {
        request[n] = '\0';

        // 查找代理请求头
        char *xff = find_header_value(request, "X-Forwarded-For");
        char *xri = find_header_value(request, "X-Real-IP");
        char *cfip = find_header_value(request, "CF-Connecting-IP");

        // 构建合并的消息
        char proxy_info[2048] = {0};
        int has_proxy_header = 0;

        if (xff || xri || cfip)
        {
            strcat(proxy_info, "访问者IP: ");

            if (xff)
            {
                char xff_value[256];
                sscanf(xff, "%255[^\r\n]", xff_value);
                strcat(proxy_info, "X-Forwarded-For=");
                strcat(proxy_info, xff_value);
                has_proxy_header = 1;
            }

            if (xri)
            {
                char xri_value[256];
                sscanf(xri, "%255[^\r\n]", xri_value);
                if (has_proxy_header)
                    strcat(proxy_info, ", ");
                strcat(proxy_info, "X-Real-IP=");
                strcat(proxy_info, xri_value);
                has_proxy_header = 1;
            }

            if (cfip)
            {
                char cfip_value[256];
                sscanf(cfip, "%255[^\r\n]", cfip_value);
                if (has_proxy_header)
                    strcat(proxy_info, ", ");
                strcat(proxy_info, "CF-Connecting-IP=");
                strcat(proxy_info, cfip_value);
            }
            if (verbose)
            {
                // 输出合并后的消息
                fprintf(stderr, "[%s] [DEBUG]: %s\n", timestamp(), proxy_info);
            }
        }

        // 解析请求行: GET /api?supernode=host:port HTTP/1.1
        char method[16], path[512], version[16];
        if (sscanf(request, "%15s %511s %15s", method, path, version) == 3)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 解析请求: method=%s, path=%s, version=%s\n",
                        timestamp(), method, path, version);
            }

            if (strncmp(path, "/api", 4) == 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 识别为 API 请求，转发到 handle_api_request()\n", timestamp());
                }
                handle_api_request(client_sock, path);
                return;
            }

            if (strncmp(path, "/refresh", 8) == 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 识别为 立即刷新 请求，转发到 handle_refresh_request()\n", timestamp());
                }
                handle_refresh_request(client_sock);
                return;
            }

            // 添加新路由
            if (strncmp(path, "/testmy?", 8) == 0)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 识别为 测测我的 请求，转发到 handle_testmy_request()\n", timestamp());
                }
                handle_testmy_request(client_sock, path);
                return;
            }

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 识别为主页请求，使用缓存响应\n", timestamp());
            }
        }
        else
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 请求行解析失败\n", timestamp());
            }
        }

        // ========== 使用缓存的 HTML ==========
        pthread_rwlock_rdlock(&g_cache_lock);

        if (g_html_cache && g_html_cache_size > 0)
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 使用缓存的 HTML (%zu 字节)\n",
                        timestamp(), g_html_cache_size);
            }

            // 检测客户端是否支持 gzip
            char *accept_encoding = find_header_value(request, "Accept-Encoding");
            int supports_gzip = (accept_encoding && strstr(accept_encoding, "gzip"));

            if (supports_gzip)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 客户端支持 gzip，使用压缩传输\n", timestamp());
                }
                send_compressed_response(client_sock, g_html_cache, g_html_cache_size);
            }
            else
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 客户端不支持 gzip，使用未压缩传输\n", timestamp());
                }
                send_chunked_response(client_sock, g_html_cache, g_html_cache_size);
            }

            pthread_rwlock_unlock(&g_cache_lock);

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 响应发送完成: %zu 字节\n",
                        timestamp(), g_html_cache_size);
            }
        }
        else
        {
            pthread_rwlock_unlock(&g_cache_lock);

            // 缓存未初始化,回退到实时生成
            if (verbose)
            {
                fprintf(stderr, "[%s] [WARN]: HTML 缓存未初始化,使用实时生成\n", timestamp());
            }

            // 动态生成代码作为后备
            pthread_rwlock_rdlock(&g_state.lock);
            size_t base_size = 50000;
            size_t per_host_size = 500 + (g_max_history * 50);
            size_t buffer_size = base_size + (g_state.host_count * per_host_size) + 10000;

            if (buffer_size < 262144)
                buffer_size = 262144;
            if (buffer_size > 10485760)
                buffer_size = 10485760;

            int host_count = g_state.host_count;
            pthread_rwlock_unlock(&g_state.lock);

            char *response = malloc(buffer_size);
            if (response)
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 分配 %zu 字节缓冲区 (主机数: %d, 历史记录: %d)\n",
                            timestamp(), buffer_size, host_count, g_max_history);
                }

                generate_html(response, buffer_size);
                size_t response_len = strlen(response);

                char *accept_encoding = find_header_value(request, "Accept-Encoding");
                int supports_gzip = (accept_encoding && strstr(accept_encoding, "gzip"));

                if (supports_gzip)
                {
                    if (verbose)
                    {
                        fprintf(stderr, "[%s] [DEBUG]: 客户端支持 gzip，使用压缩传输\n", timestamp());
                    }
                    send_compressed_response(client_sock, response, response_len);
                }
                else
                {
                    if (verbose)
                    {
                        fprintf(stderr, "[%s] [DEBUG]: 客户端不支持 gzip，使用未压缩传输\n", timestamp());
                    }
                    send_chunked_response(client_sock, response, response_len);
                }

                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: 响应发送完成: %zu 字节\n", timestamp(), response_len);
                }

                free(response);
            }
            else
            {
                if (verbose)
                {
                    fprintf(stderr, "[%s] [ERROR]: 无法分配 %zu 字节缓冲区\n", timestamp(), buffer_size);
                }
            }
        }
    }
    else if (n == 0)
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 客户端关闭连接\n", timestamp());
        }
    }
    else
    {
        if (verbose)
        {
            fprintf(stderr, "[%s] [ERROR]: recv() 错误: %s\n", timestamp(), strerror(errno));
        }
    }

    close(client_sock);
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: HTTP 请求处理完成,连接已关闭\n", timestamp());
    }
}

// 监控线程
void *monitor_thread(void *arg)
{
    (void)arg;
    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 监控线程启动（并行检测模式，最多 %d 个并发）\n",
                timestamp(), g_max_parallel_checks);
    }

    int round = 0;
    while (g_state.running)
    {
        round++;

        // 检查配置文件是否被修改
        if (g_state.config_file_path[0] != '\0')
        {
            struct stat st;
            if (stat(g_state.config_file_path, &st) == 0)
            {
                if (st.st_mtime > g_state.config_mtime)
                {
                    // 转换旧时间
                    struct tm *old_tm = localtime(&g_state.config_mtime);
                    char old_time_str[64];
                    strftime(old_time_str, sizeof(old_time_str), "%Y年%m月%d日 %H时%M分%S秒", old_tm);

                    // 转换新时间
                    struct tm *new_tm = localtime(&st.st_mtime);
                    char new_time_str[64];
                    strftime(new_time_str, sizeof(new_time_str), "%Y年%m月%d日 %H时%M分%S秒", new_tm);

                    fprintf(stderr, "[%s] [DEBUG]: 配置文件已修改 (上次是%s, 当前为%s)重新加载\n",
                            timestamp(), old_time_str, new_time_str);

                    g_state.config_mtime = st.st_mtime;
                    reload_config();
                }
            }
            else if (verbose)
            {
                fprintf(stderr, "[%s] [WARN]: 无法访问配置文件: %s\n",
                        timestamp(), strerror(errno));
            }
        }

        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 开始第 %d 轮检测 (共 %d 个主机)\n",
                    timestamp(), round, g_state.host_count);
        }

        // ========== 并行检测逻辑 ==========
        int total_hosts = g_state.host_count;

        for (int i = 0; i < total_hosts; i += g_max_parallel_checks)
        {
            // 计算本批次要检测的主机数量
            int batch_size = (i + g_max_parallel_checks > total_hosts)
                                 ? (total_hosts - i)
                                 : g_max_parallel_checks;

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 开始批次 %d/%d，检测 %d 个主机\n",
                        timestamp(), i / g_max_parallel_checks + 1,
                        (total_hosts + g_max_parallel_checks - 1) / g_max_parallel_checks,
                        batch_size);
            }

            // 准备任务和线程数组
            check_task_t tasks[g_max_parallel_checks];
            pthread_t threads[g_max_parallel_checks];

            // 启动一批检测线程
            for (int j = 0; j < batch_size; j++)
            {
                int idx = i + j;
                host_stats_t *h = &g_state.hosts[idx];

                // 初始化任务
                memset(&tasks[j], 0, sizeof(check_task_t));
                strncpy(tasks[j].host, h->host, sizeof(tasks[j].host) - 1);
                tasks[j].host[sizeof(tasks[j].host) - 1] = '\0';
                tasks[j].port = h->port;
                tasks[j].host_index = idx;

                // 创建线程
                if (pthread_create(&threads[j], NULL, check_host_worker, &tasks[j]) != 0)
                {
                    fprintf(stderr, "[%s] [ERROR]: 无法创建检测线程 %d: %s\n",
                            timestamp(), j, strerror(errno));
                    // 如果线程创建失败，直接在主线程中执行
                    check_host_worker(&tasks[j]);
                }
            }

            // 等待所有线程完成
            for (int j = 0; j < batch_size; j++)
            {
                pthread_join(threads[j], NULL);
            }

            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 批次完成，开始更新统计数据\n", timestamp());
            }

            // 批量更新统计数据（一次性加写锁）
            pthread_rwlock_wrlock(&g_state.lock);

            for (int j = 0; j < batch_size; j++)
            {
                int idx = tasks[j].host_index;
                host_stats_t *h = &g_state.hosts[idx];

                // 更新统计
                h->total_checks++;
                if (tasks[j].v1_ok)
                    h->success_v1++;
                if (tasks[j].v2_ok)
                    h->success_v2++;
                if (tasks[j].v2s_ok)
                    h->success_v2s++;
                if (tasks[j].v3_ok)
                    h->success_v3++;
                h->last_check = time(NULL);

                // 检测状态变化
                if (g_callback_script[0] != '\0' && h->last_online_status != tasks[j].is_online)
                {
                    // 避免首次检测时就是在线的情况触发
                    if (h->last_online_status != -1 || !tasks[j].is_online)
                    {
                        call_status_change_script(h, tasks[j].is_online,
                                                  tasks[j].v1_ok, tasks[j].v2_ok,
                                                  tasks[j].v2s_ok, tasks[j].v3_ok);
                    }
                }
                h->last_online_status = tasks[j].is_online;

                // 添加检测记录到历史数组
                add_check_record(h, tasks[j].is_online);

                // 更新状态文本
                snprintf(h->last_status, sizeof(h->last_status),
                         tasks[j].is_online ? "✓ 在线" : "✗ 离线");

                // 保存历史记录到文件
                save_history(h);

                if (verbose)
                {
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 检测结果: %s (v1:%s v2:%s v2s:%s v3:%s)\n",
                            timestamp(), h->host, h->port,
                            tasks[j].is_online ? "在线" : "离线",
                            tasks[j].v1_ok ? "✓" : "✗",
                            tasks[j].v2_ok ? "✓" : "✗",
                            tasks[j].v2s_ok ? "✓" : "✗",
                            tasks[j].v3_ok ? "✓" : "✗");

                    float uptime = calculate_uptime(h);
                    fprintf(stderr, "[%s] [DEBUG]: %s:%d 连通率: %.2f%% (基于最近 %d 次检测)\n",
                            timestamp(), h->host, h->port, uptime, h->history_count);
                }
            }

            pthread_rwlock_unlock(&g_state.lock);
            // 更新 HTML 缓存
            update_html_cache();
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

// 人类可读格式转换
static void format_size(size_t bytes, char *output, size_t output_size)
{
    const char *units[] = {"B", "K", "M", "G", "T"};
    int unit_index = 0;
    double size = (double)bytes;

    while (size >= 1024.0 && unit_index < 4)
    {
        size /= 1024.0;
        unit_index++;
    }

    if (unit_index == 0)
    {
        snprintf(output, output_size, "%zu%s", bytes, units[unit_index]);
    }
    else
    {
        snprintf(output, output_size, "%.2f%s", size, units[unit_index]);
    }
}

// 计算总存储大小
static size_t calculate_total_storage_size(void)
{
    size_t total = 0;

    for (int i = 0; i < g_state.host_count; i++)
    {
        host_stats_t *h = &g_state.hosts[i];
        // 每个主机的存储大小
        size_t host_size = sizeof(int) * 2 +                         // history_index + history_count
                           sizeof(check_record_t) * h->max_history + // history数组
                           sizeof(int) * 5;                          // total_checks + success_v1/v2/v2s/v3
        total += host_size;
    }

    return total;
}

// 信号处理函数 - 保存所有历史记录后退出
void signal_handler(int signum)
{
    if (verbose)
    {
        fprintf(stderr, "\n[%s] [INFO]: 收到信号 %d，正在保存历史检测记录并退出...\n",
                timestamp(), signum);
    }

    // 停止监控线程
    g_state.running = 0;

    // 保存所有主机的历史记录
    pthread_rwlock_wrlock(&g_state.lock);
    for (int i = 0; i < g_state.host_count; i++)
    {
        save_history(&g_state.hosts[i]);
        if (verbose)
        {
            fprintf(stderr, "[%s] [DEBUG]: 已保存 %s:%d 的历史检测记录\n",
                    timestamp(), g_state.hosts[i].host, g_state.hosts[i].port);
        }
    }
    pthread_rwlock_unlock(&g_state.lock);
    pthread_rwlock_destroy(&g_state.lock);
    // 清理 HTML 缓存
    pthread_rwlock_wrlock(&g_cache_lock);
    if (g_html_cache)
    {
        free(g_html_cache);
        g_html_cache = NULL;
    }
    pthread_rwlock_unlock(&g_cache_lock);
    pthread_rwlock_destroy(&g_cache_lock);

    if (verbose)
    {
        fprintf(stderr, "[%s] [INFO]: 所有历史检测记录已保存，程序退出\n", timestamp());
    }

    exit(0);
}

static int calculate_min_interval(int host_count, int parallel_checks)
{
    // 保守估计：每个主机平均 2 秒（考虑重试）
    int avg_check_time_sec = 2;

    // 计算最小间隔（秒）
    int min_interval_sec = (host_count * avg_check_time_sec) / parallel_checks;

    // 转换为分钟，向上取整
    int min_interval_min = (min_interval_sec + 59) / 60;

    // 最小不低于 1 分钟
    return (min_interval_min < 1) ? 1 : min_interval_min;
}

// 打印帮助信息
static void print_help(const char *prog_name)
{
    printf("N2N supernode 检测工具\n\n");
    printf("用法: %s [选项] <主机1:端口1> [主机2:端口2] ...\n\n", prog_name);
    printf("选项:\n");
    printf("  -p <端口>       服务主页监听端口 (默认: 8585)\n");
    printf("  -i <分钟>       自动探测间隔时间 (默认: 5)\n");
    printf("  -r <分钟>       允许主页里手动探测的最小间隔时间 (默认: 5)\n");
    printf("  -t <秒>         探测超时时间 (默认: 1)\n");
    printf("  -z <次数>       探测超时或失败后最大重试次数 (默认: 5)\n");
    printf("  -x <数量>       并行检测的最大线程数 (默认: 5, 范围: 1-20)\n");
    printf("  -j <数量>       保存历史检测记录条数 (默认: 300条/主机)\n");
    printf("  -d <路径>       历史检测记录保存目录 (默认: /tmp/n2n_monitor)\n");
    printf("  -f <文件>       从指定文件读取主机列表 (一行一个，支持备注)\n");
    printf("  -w <文件>       探测时当主机状态发生变化后调用的脚本\n");
    printf("  -c <社区名>     探测使用的社区名称 (默认: N2N_check_bot)\n");
    printf("  -m <MAC地址>    探测使用的MAC地址 (默认: a1:b2:c3:d4:f5:06)\n");
    printf("  -6              服务主页启用 IPv6 支持\n");
    printf("  -s              启用输出到系统日志\n");
    printf("  -v              详细模式（显示调试信息）\n");
    printf("  -h              显示此帮助信息\n\n");
    printf("主机列表文件格式:\n");
    printf("  host:port|备注|主页展示的主机名\n");
    printf("  例如: n2n.example.com:10086|北京电信|隐私.com\n\n");
    printf("回调脚本传递参数:\n");
    printf("  主机(host:port) 版本(v1 v2 v2s v3 Unknown) 状态(up down)\n");
    printf("  例如: script_file.sh n2n.example.com:10086 v1 up\n");
    printf("  例如: script_file.sh n2n.example.com:10082 Unknown down\n\n");
    printf("命令示例:\n");
    printf("  %s -p 8080 -i 10 n2n.example.com:10086 192.168.1.1:10090\n", prog_name);
    printf("  %s -v -6 \"supernode.example.com:7777|北京电信\" \"192.168.1.1:10090|自建\"\n", prog_name);
    printf("  %s -p 8080 -i 10 -f n2n_host.conf\n", prog_name);
    printf("\n");
}

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    srand(time(NULL));

    int http_port = 8585;
    int check_interval = 5;
    char *config_file = NULL;
    int arg_start = 1;
    int use_ipv6 = 0; // 默认仅 IPv4
    int original_stderr = -1;

    // 如果没有任何参数,显示帮助信息
    // if (argc == 1)
    // {
    //    print_help(argv[0]);
    //    return 0;
    // }
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
        else if (strcmp(argv[arg_start], "-s") == 0)
        {
            g_enable_syslog = 1;
            arg_start++;
            fprintf(stderr, "[%s] [INFO]: 系统日志输出已启用\n", timestamp());
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
            // if (verbose)
            // {
            fprintf(stderr, "[%s] [DEBUG]: 自动检测间隔时间: %d分钟\n",
                    timestamp(), check_interval);
            // }
        }
        else if (strcmp(argv[arg_start], "-t") == 0 && arg_start + 1 < argc)
        {
            int timeout_sec = atoi(argv[arg_start + 1]);
            if (timeout_sec <= 0 || timeout_sec > 120)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的超时时间 %d 秒 (范围: 1-120秒)\n",
                        timestamp(), timeout_sec);
                return 1;
            }
            g_timeout_ms = timeout_sec * 1000; // 转换为毫秒
            arg_start += 2;
            // if (verbose)
            // {
            fprintf(stderr, "[%s] [DEBUG]: 检测超时时间: %d秒 (%ldms)\n",
                    timestamp(), timeout_sec, g_timeout_ms);
            // }
        }
        else if (strcmp(argv[arg_start], "-z") == 0 && arg_start + 1 < argc)
        {
            g_max_retries = atoi(argv[arg_start + 1]);
            if (g_max_retries <= 0 || g_max_retries > 20)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的重试次数 %d (范围: 1-20)\n",
                        timestamp(), g_max_retries);
                return 1;
            }
            arg_start += 2;
            // if (verbose) {
            fprintf(stderr, "[%s] [DEBUG]: 检测超时最大重试次数: %d 次\n",
                    timestamp(), g_max_retries);
            // }
        }
        else if (strcmp(argv[arg_start], "-r") == 0 && arg_start + 1 < argc)
        {
            manual_refresh_interval = atoi(argv[arg_start + 1]);
            if (manual_refresh_interval <= 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的刷新间隔 %d\n", timestamp(), manual_refresh_interval);
                return 1;
            }
            arg_start += 2;
            // if (verbose)
            // {
            fprintf(stderr, "[%s] [DEBUG]: 主页手动检测最小间隔时间: %d秒\n",
                    timestamp(), manual_refresh_interval);
            // }
        }
        else if (strcmp(argv[arg_start], "-j") == 0 && arg_start + 1 < argc)
        {
            g_max_history = atoi(argv[arg_start + 1]);
            if (g_max_history <= 0 || g_max_history > 10000)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的历史检测记录数量 %d (范围: 1-10000)\n",
                        timestamp(), g_max_history);
                return 1;
            }
            arg_start += 2;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 最大历史检测记录保存数量: %d条/主机\n",
                        timestamp(), g_max_history);
            }
        }
        else if (strcmp(argv[arg_start], "-d") == 0 && arg_start + 1 < argc)
        {
            strncpy(g_state_dir, argv[arg_start + 1], sizeof(g_state_dir) - 1);
            g_state_dir[sizeof(g_state_dir) - 1] = '\0';
            arg_start += 2;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 历史检测记录保存路径: %s\n",
                        timestamp(), g_state_dir);
            }
        }
        else if (strcmp(argv[arg_start], "-x") == 0 && arg_start + 1 < argc)
        {
            int user_specified = atoi(argv[arg_start + 1]);

            // 检测 CPU 核心数
            int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
            if (cpu_cores <= 0)
            {
                cpu_cores = 1;
            }

            // 计算推荐的最大线程数
            int recommended_max = (cpu_cores <= 2) ? 3 : (cpu_cores <= 4) ? cpu_cores
                                                     : (cpu_cores < 10)   ? cpu_cores
                                                                          : 10;

            // 验证用户输入
            if (user_specified <= 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的并行检测线程数 %d (必须大于 0)\n",
                        timestamp(), user_specified);
                return 1;
            }

            // 如果超出推荐范围，给出警告并调整
            if (user_specified > recommended_max)
            {
                fprintf(stderr, "[%s] [WARN]: 您指定的并行线程数 %d 超出推荐值 (设备CPU 核心数: %d, 推荐最大: %d)\n",
                        timestamp(), user_specified, cpu_cores, recommended_max);
                fprintf(stderr, "[%s] [WARN]: 已自动调整为推荐值: %d\n",
                        timestamp(), recommended_max);
                g_max_parallel_checks = recommended_max;
            }
            else if (user_specified > 20)
            {
                fprintf(stderr, "[%s] [WARN]: 您指定的并行线程数 %d 超出系统限制 (最大: 20)\n",
                        timestamp(), user_specified);
                fprintf(stderr, "[%s] [WARN]: 已自动调整为系统最大值: 20\n", timestamp());
                g_max_parallel_checks = 20;
            }
            else
            {
                g_max_parallel_checks = user_specified;
                fprintf(stderr, "[%s] [INFO]: 并行检测线程数: %d\n",
                        timestamp(), g_max_parallel_checks);
            }

            arg_start += 2;
        }
        else if (strcmp(argv[arg_start], "-f") == 0 && arg_start + 1 < argc)
        {
            config_file = argv[arg_start + 1];
            strncpy(g_state.config_file_path, config_file, sizeof(g_state.config_file_path) - 1);
            arg_start += 2;
            // if (verbose)
            // {
            fprintf(stderr, "[%s] [DEBUG]: 主机列表文件: %s\n", timestamp(), config_file);
            // }
        }
        else if (strcmp(argv[arg_start], "-w") == 0 && arg_start + 1 < argc)
        {
            strncpy(g_callback_script, argv[arg_start + 1], sizeof(g_callback_script) - 1);
            g_callback_script[sizeof(g_callback_script) - 1] = '\0';
            // 验证脚本
            if (access(g_callback_script, F_OK) != 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 回调脚本不存在: %s\n",
                        timestamp(), g_callback_script);
                return 1;
            }
            else if (access(g_callback_script, X_OK) != 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 回调脚本无执行权限: %s\n",
                        timestamp(), g_callback_script);
                fprintf(stderr, "[%s] [INFO]: 请运行: chmod +x %s\n",
                        timestamp(), g_callback_script);
                return 1;
            }
            else
            {
                // if (verbose)
                // {
                fprintf(stderr, "[%s] [INFO]: 回调脚本已配置: %s\n",
                        timestamp(), g_callback_script);
                // }
            }
            arg_start += 2;
        }
        else if (strcmp(argv[arg_start], "-c") == 0 && arg_start + 1 < argc)
        {
            const char *community_input = argv[arg_start + 1];
            size_t community_len = strlen(community_input);

            // 检查社区名长度是否超过 14 字符
            if (community_len > 14)
            {
                fprintf(stderr, "[%s] [ERROR]: 您输入的社区名社区名 %s 长度超出限制: %zu 字符 (最大: 14 字符)\n",
                        timestamp(), community_input, community_len);
                fprintf(stderr, "[%s] [INFO]: 请使用不超过 14 个字符的社区名！\n",
                        timestamp());
                return 1; // 退出程序
            }
            strncpy(g_community, argv[arg_start + 1], N2N_COMMUNITY_SIZE - 1);
            g_community[N2N_COMMUNITY_SIZE - 1] = '\0';
            arg_start += 2;
            // if (verbose)
            // {
            fprintf(stderr, "[%s] [DEBUG]: 探测使用的社区名: %s\n", timestamp(), g_community);
            // }
        }
        else if (strcmp(argv[arg_start], "-m") == 0 && arg_start + 1 < argc)
        {
            if (parse_mac(argv[arg_start + 1], g_mac) < 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 无效的 MAC 地址格式: %s\n", timestamp(), argv[arg_start + 1]);
                fprintf(stderr, "正确格式如: a1:b2:c3:d4:f5:06\n");
                return 1;
            }
            arg_start += 2;
            // if (verbose)
            // {
            fprintf(stderr, "[%s] [DEBUG]: 探测使用的 MAC 地址: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    timestamp(), g_mac[0], g_mac[1], g_mac[2], g_mac[3], g_mac[4], g_mac[5]);
            // }
        }
        else if (strcmp(argv[arg_start], "-6") == 0)
        {
            use_ipv6 = 1;
            arg_start++;
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 启用 IPv6 支持\n", timestamp());
            }
        }
        else
        {
            break;
        }
    }

    // 在初始化状态之前,设置 syslog 重定向

    if (g_enable_syslog)
    {
        // 保存原始 stderr
        original_stderr = dup(STDERR_FILENO);

        // 创建管道用于 stderr 重定向
        if (pipe(g_syslog_pipe) == -1)
        {
            fprintf(stderr, "[%s] [ERROR]: 无法创建 syslog 管道: %s\n", timestamp(), strerror(errno));
            fprintf(stderr, "[%s] [WARN]: 系统日志功能将被禁用\n", timestamp());
            g_enable_syslog = 0;
        }
        else
        {
            g_syslog_running = 1;

            // 启动 syslog 转发线程
            if (pthread_create(&g_syslog_thread, NULL, syslog_forwarder_thread, &original_stderr) != 0)
            {
                fprintf(stderr, "[%s] [ERROR]: 无法创建 syslog 线程: %s\n", timestamp(), strerror(errno));
                fprintf(stderr, "[%s] [WARN]: 系统日志功能将被禁用\n", timestamp());
                close(g_syslog_pipe[0]);
                close(g_syslog_pipe[1]);
                g_enable_syslog = 0;
                g_syslog_running = 0;
            }
            else
            {
                // 重定向 stderr 到管道
                if (dup2(g_syslog_pipe[1], STDERR_FILENO) == -1)
                {
                    fprintf(stderr, "[%s] [ERROR]: 无法重定向 stderr: %s\n", timestamp(), strerror(errno));
                    fprintf(stderr, "[%s] [WARN]: 系统日志功能将被禁用\n", timestamp());
                    g_syslog_running = 0;
                    pthread_cancel(g_syslog_thread);
                    close(g_syslog_pipe[0]);
                    close(g_syslog_pipe[1]);
                    g_enable_syslog = 0;
                }
                else
                {
                    close(g_syslog_pipe[1]); // 关闭写端的原始 fd
                    fprintf(stderr, "[%s] [INFO]: 系统日志转发已启动\n", timestamp());
                }
            }
        }
    }

    // 初始化状态
    pthread_rwlock_init(&g_state.lock, NULL);
    pthread_rwlock_init(&g_cache_lock, NULL);
    g_state.check_interval_minutes = check_interval;
    g_state.start_time = time(NULL);
    g_state.running = 1;
    // 自动检测 CPU 核心数
    int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_cores <= 0)
    {
        cpu_cores = 1; // 检测失败时默认为 1
        if (verbose)
        {
            fprintf(stderr, "[%s] [WARN]: 无法检测 CPU 核心数，默认为 1\n", timestamp());
        }
    }

    // 如果用户没有通过 -n 参数指定，则自动设置
    if (g_max_parallel_checks == 5)
    { // 5 是默认值，说明用户没有指定
        if (cpu_cores <= 2)
        {
            g_max_parallel_checks = 3; // 单核双线程用 3
        }
        else if (cpu_cores <= 4)
        {
            g_max_parallel_checks = cpu_cores; // 2-4 核用实际核心数
        }
        else
        {
            g_max_parallel_checks = (cpu_cores < 10) ? cpu_cores : 10; // 最多 10 个
        }
        fprintf(stderr, "[%s] [INFO]: 自动检测到 %d 个 CPU 核心，设置并行检测线程数为 %d\n",
                timestamp(), cpu_cores, g_max_parallel_checks);
    }

    // 注册信号处理函数
    signal(SIGTERM, signal_handler); // kill 命令
    signal(SIGINT, signal_handler);  // Ctrl+C
    signal(SIGHUP, signal_handler);  // 终端断开
    signal(SIGPIPE, SIG_IGN);        // 忽略 SIGPIPE 信号

    if (verbose)
    {
        fprintf(stderr, "[%s] [DEBUG]: 已注册信号处理函数 (SIGTERM, SIGINT, SIGHUP)\n",
                timestamp());
    }

    // 创建状态目录
    struct stat st = {0};
    if (stat(g_state_dir, &st) == -1)
    {
        if (mkdir(g_state_dir, 0755) == -1)
        {
            fprintf(stderr, "[%s] [ERROR]: 无法创建历史检测记录保存的目录 %s: %s\n",
                    timestamp(), g_state_dir, strerror(errno));
            fprintf(stderr, "[%s] [WARN]: 历史检测记录功能将不可用\n", timestamp());
        }
        else
        {
            if (verbose)
            {
                fprintf(stderr, "[%s] [DEBUG]: 已创建历史检测记录保存目录: %s\n", timestamp(), g_state_dir);
            }
        }
    }

    // 读取配置文件
    if (config_file)
    {
        load_config(config_file);
        // 记录初始修改时间
        struct stat st;
        if (stat(config_file, &st) == 0)
        {
            g_state.config_mtime = st.st_mtime;
        }
    }

    // 根据主机数量验证间隔参数
    if (g_state.host_count > 0)
    {
        int min_check_interval = calculate_min_interval(g_state.host_count, g_max_parallel_checks);
        int min_refresh_interval = min_check_interval; // 手动刷新至少与自动检测相同

        // 验证 -i 参数
        if (check_interval < min_check_interval)
        {
            fprintf(stderr, "[%s] [WARN]: 自动检测间隔 %d 分钟过短（主机数: %d, 并行线程: %d）\n",
                    timestamp(), check_interval, g_state.host_count, g_max_parallel_checks);
            fprintf(stderr, "[%s] [WARN]: 推荐最小间隔: %d 分钟（基于 %d 个主机 / %d 并行线程）\n",
                    timestamp(), min_check_interval, g_state.host_count, g_max_parallel_checks);
            fprintf(stderr, "[%s] [WARN]: 已自动调整为推荐值: %d 分钟\n",
                    timestamp(), min_check_interval);
            check_interval = min_check_interval;
            g_state.check_interval_minutes = check_interval;
        }

        // 验证 -r 参数
        if (manual_refresh_interval < min_refresh_interval)
        {
            fprintf(stderr, "[%s] [WARN]: 手动检测间隔 %d 分钟过短（主机数: %d, 并行线程: %d）\n",
                    timestamp(), manual_refresh_interval, g_state.host_count, g_max_parallel_checks);
            fprintf(stderr, "[%s] [WARN]: 推荐最小间隔: %d 分钟\n",
                    timestamp(), min_refresh_interval);
            fprintf(stderr, "[%s] [WARN]: 已自动调整为推荐值: %d 分钟\n",
                    timestamp(), min_refresh_interval);
            manual_refresh_interval = min_refresh_interval;
        }
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
        char display_name[256] = {0}; // 新增: 前端显示主机名

        // 解析格式: host:port|备注|前端显示主机名 或 host:port|备注 或 host:port
        char *first_pipe = strchr(host_str, '|');
        if (first_pipe)
        {
            *first_pipe = '\0';
            char *second_pipe = strchr(first_pipe + 1, '|');
            if (second_pipe)
            {
                // 三段式格式: host:port|备注|前端显示主机名
                *second_pipe = '\0';
                strncpy(note, first_pipe + 1, sizeof(note) - 1);
                strncpy(display_name, second_pipe + 1, sizeof(display_name) - 1);
            }
            else
            {
                // 兼容旧格式: host:port|备注
                strncpy(note, first_pipe + 1, sizeof(note) - 1);
            }
        }
        // 解析端口 - 支持特殊前缀
        char *port_str = NULL;
        int has_special_prefix = 0;

        // 检查特殊前缀
        if (strncmp(host_str, "txt:", 4) == 0)
        {
            has_special_prefix = 1;
            // 跳过 txt: 前缀后再查找端口
            port_str = strchr(host_str + 4, ':');
        }
        else if (strncmp(host_str, "http:", 5) == 0)
        {
            has_special_prefix = 1;
            // 检查是否有路径
            const char *host_part = host_str + 5;
            char *slash = strchr(host_part, '/');

            if (slash)
            {
                // 有路径,不提取端口,保持完整主机名
                port_str = NULL;
                port = 0; // 直接设为 0
            }
            else
            {
                // 没有路径,正常查找端口
                port_str = strchr(host_part, ':');
            }
        }
        else
        {
            // 普通主机
            port_str = strchr(host_str, ':');
        }

        if (port_str)
        {
            *port_str = '\0';
            port = atoi(port_str + 1);

            // 特殊前缀允许端口为 0
            if (has_special_prefix)
            {
                if (port < 0 || port > 65535)
                {
                    fprintf(stderr, "[%s] [ERROR]: 无效的端口号 %d (主机: %s)\n", timestamp(), port, host_str);
                    free(host_str);
                    continue;
                }
            }
            else
            {
                // 普通主机端口必须有效
                if (port <= 0 || port > 65535)
                {
                    fprintf(stderr, "[%s] [ERROR]: 无效的端口号 %d (主机: %s)\n", timestamp(), port, host_str);
                    free(host_str);
                    continue;
                }
            }
        }
        else
        {
            // 没有端口号
            if (has_special_prefix)
            {
                // 特殊前缀允许无端口,自动填充为 0
                port = 0;
            }
        }
        strncpy(host, host_str, sizeof(host) - 1);

        // 【新增】检查是否重复
        int is_duplicate = 0;
        for (int j = 0; j < g_state.host_count; j++)
        {
            if (strcmp(g_state.hosts[j].host, host) == 0 &&
                g_state.hosts[j].port == port)
            {
                is_duplicate = 1;
                fprintf(stderr, "[%s] [WARN]: 忽略重复的主机 (命令行参数 %d): %s:%d\n",
                        timestamp(), i + 1, host, port);
                break;
            }
        }

        if (is_duplicate)
        {
            free(host_str);
            continue; // 跳过这个重复的主机
        }

        host_stats_t *h = &g_state.hosts[g_state.host_count];
        strncpy(h->host, host_str, sizeof(h->host) - 1);
        h->port = port;
        strncpy(h->note, note, sizeof(h->note) - 1);
        strncpy(h->display_name, display_name, sizeof(h->display_name) - 1);

        // 初始化 max_history 并分配内存
        h->max_history = g_max_history;
        h->history = calloc(g_max_history, sizeof(check_record_t));
        if (!h->history)
        {
            fprintf(stderr, "[%s] [ERROR]: 无法为 %s:%d 分配历史记录内存，跳过这个主机\n",
                    timestamp(), host_str, port);
            free(host_str);
            continue;
        }

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
        fprintf(stderr, "[%s] [WARN]: 当前没有配置任何主机,仅启用自建测检测功能\n", timestamp());
    }

    // printf("[%s] [INFO]: 共计检测 %d 个主机\n", timestamp(), g_state.host_count);
    //  计算并输出存储信息
    size_t total_size = calculate_total_storage_size();
    char size_str[64];
    format_size(total_size, size_str, sizeof(size_str));

    fprintf(stderr, "[%s] [INFO]: 历史检测记录配置:\n", timestamp());
    fprintf(stderr, "[%s] [INFO]:   - 保存路径: %s\n", timestamp(), g_state_dir);
    fprintf(stderr, "[%s] [INFO]:   - 最大记录数: %d 条/主机\n", timestamp(), g_max_history);
    fprintf(stderr, "[%s] [INFO]:   - 主机数量: %d 个\n", timestamp(), g_state.host_count);
    if (g_state.host_count > 0)
    {
        fprintf(stderr, "[%s] [INFO]:   - 预计占用: %s\n", timestamp(), size_str);
    }
    else
    {
        fprintf(stderr, "[%s] [INFO]:   - 预计占用: 0B (未配置主机)\n", timestamp());
    }

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
            if (verbose)
            {
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
            }
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
