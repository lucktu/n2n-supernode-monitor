# 一个定时检测N2N supernode 可用性的工具

### UI：
<img width="1566" height="994" alt="image" src="https://github.com/user-attachments/assets/3a4f5c39-5aea-4b96-90cf-8d786bbaecbe" />

```
N2N supernode 检测工具

用法: ./n2n_check_http [选项] <主机1:端口1> [主机2:端口2] ...

选项:
  -p <端口>       服务主页监听端口 (默认: 8585)
  -i <分钟>       指定探测间隔时间（分钟）(默认: 1)
  -f <文件>       从配置文件读取主机列表(支持备注)
  -c <社区名>     指定探测使用的社区名称 (默认: N2N_check_bot)
  -m <MAC地址>    指定探测使用的MAC地址,格式: a1:b2:c3:d4:f5:g6 (默认: a1:b2:c3:d4:f5:06)
  -4              仅使用 IPv4 (默认)
  -6              同时支持 IPv4 和 IPv6

  -v              详细模式（显示调试信息）
  -h              显示此帮助信息
配置文件格式:
  host:port|备注
  例如: n2n.example.com:10086|北京电信

命令示例:
  ./edge2 -p 8080 -i 2 n2n.example.com:10086 192.168.1.1:10090
  ./edge2 -v -6 "supernode.example.com:7777|北京电信" "192.168.1.1:10090|自建"
  ./edge2 -p 8080 -i 2 -f n2n_host.conf
```

- 命令行添加备注需要英文的双引号 `"` 包裹才行，配置文件则无需双引号
- 配置文件一行一个服务器 `#` 为注释不会解析，`|` 为分隔备注使用的

### 启动命令示例：

#### ① 命令行：

```
# 采用配置文件并后台运行
nohup ./n2n_check_http -p 8585 -i 5 -f /etc/n2n_hosts.conf > /dev/null 2>&1 &
```

#### ② systemd 服务：

```
[Unit]  
Description=N2N Supernode Monitor  
After=network.target  
  
[Service]  
Type=simple  
ExecStart=/usr/local/bin/n2n_check_http -p 8585 -i 5 -f /etc/n2n_hosts.conf  
StandardOutput=null  
StandardError=null  
Restart=always  
RestartSec=10  
  
[Install]  
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload  
sudo systemctl start n2n-monitor  # 启动
sudo systemctl enable n2n-monitor  # 开机自启
```
