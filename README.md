# 一个定时检测N2N supernode 可用性的工具

[![问问 AI](https://deepwiki.com/badge.svg)](https://deepwiki.com/lmq8267/n2n-supernode-monitor)

### UI：
<img width="1566" height="994" alt="image" src="https://github.com/user-attachments/assets/3a4f5c39-5aea-4b96-90cf-8d786bbaecbe" />

```
N2N supernode 检测工具

用法: ./n2n_check_http [选项] <主机1:端口1> [主机2:端口2] ...

选项:
  -p <端口>       服务主页监听端口 (默认: 8585)
  -i <分钟>       指定自动探测间隔时间（分钟）(默认: 1)
  -r <分钟>       指定主页手动刷新探测间隔时间（分钟）(默认: 1)
  -f <文件>       从配置文件读取主机列表(支持备注)
  -c <社区名>     指定探测使用的社区名称 (默认: N2N_check_bot)
  -m <MAC地址>    指定探测使用的MAC地址,格式: a1:b2:c3:d4:f5:g6 (默认: a1:b2:c3:d4:f5:06)
  -4              仅使用 IPv4 (默认)
  -6              同时支持 IPv4 和 IPv6

  -v              详细模式（显示调试信息）
  -h              显示此帮助信息

配置文件格式:
  host:port|备注|主页展示的主机名
  例如: n2n.example.com:10086|北京电信|隐私.com

命令示例:
  ./n2n_check_http -p 8080 -i 2 n2n.example.com:10086 192.168.1.1:10090
  ./n2n_check_http -v -6 "supernode.example.com:7777|北京电信" "192.168.1.1:10090|自建"
  ./n2n_check_http -p 8080 -i 2 -f n2n_host.conf
```

- 命令行添加备注需要英文的双引号 `"` 包裹才行，配置文件则无需双引号
- 配置文件一行一个服务器 `#` 为注释不会解析，`|` 为分隔备注使用的

### 启动命令示例：

#### ① 命令行：

```
# 采用配置文件并后台运行
nohup ./n2n_check_http -p 8585 -i 5 -f /etc/n2n_hosts.conf > /dev/null 2>&1 &
```
- 在openwrt里因为时区问题 可能需要指定时区启动 如 `TZ=utc-8`

```
TZ=utc-8 ./n2n_check_http -p 8585 -i 5 -f /etc/n2n_hosts.conf > /dev/null 2>&1 &
```

#### ② systemd 服务： 

写入 `/etc/systemd/system/n2n-monitor.service`

```
[Unit]  
Description=N2N Supernode Monitor  
After=network.target  
  
[Service]  
Type=simple  
ExecStart=/usr/local/bin/n2n_check_http -p 8585 -i 5 -f /etc/n2n_hosts.conf  
StandardOutput=journal    
StandardError=journal  
Restart=always  
RestartSec=10  
  
[Install]  
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload  # 重新加载 systemd 配置

sudo systemctl start n2n-monitor  # 启动服务

sudo systemctl enable n2n-monitor  # 设置开机自启
 
sudo systemctl stop n2n-monitor  # 停止服务 
  
sudo systemctl disable n2n-monitor  # 禁用开机自启  
  
sudo systemctl status n2n-monitor # 查看服务状态
 
sudo journalctl -u n2n-monitor -f # 查看服务日志 
```

##### 网页嵌套svg图标 ：

  <img width="208" height="33" alt="image" src="https://github.com/user-attachments/assets/2b38f3ea-63bf-4809-9327-325bd7b232b7" />

- 在html网页中嵌入图片并设置宽度、高度与替代文字（alt），可以通过 HTML 的 <img> 标签实现。语法如下：

```
<img src="https://example.com/api/?supernode=n2n.example.com:10086" alt="" width="200" height="100">

```

- 自适应大小:

```
<img src="https://example.com/api/?supernode=n2n.example.com:10086" alt="" style="width:100%; height:auto;">

```
