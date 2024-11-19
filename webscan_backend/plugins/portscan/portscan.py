# -*- coding:utf-8 -*-

# Reference: https://github.com/AnthraX1/InsightScan/blob/master/scanner.py

import socket
import re
import concurrent.futures
import sys
import os
from urllib import parse

sys.path.append(os.getcwd())

THREADNUM = 64  # 线程数

SIGNS = (
    # 协议 | 版本 | 关键字
    b'smb|smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
    b"xmpp|xmpp|^\<\?xml version='1.0'\?\>",
    b'netbios|netbios|^\x79\x08.*BROWSE',
    b'http|http|HTTP/1.1',
    b'netbios|netbios|^\x79\x08.\x00\x00\x00\x00',
    b'netbios|netbios|^\x05\x00\x0d\x03',
    b'netbios|netbios|^\x82\x00\x00\x00',
    b'netbios|netbios|\x83\x00\x00\x01\x8f',
    b'backdoor|backdoor|^500 Not Loged in',
    b'backdoor|backdoor|GET: command',
    b'backdoor|backdoor|sh: GET:',
    b'bachdoor|bachdoor|[a-z]*sh: .* command not found',
    b'backdoor|backdoor|^bash[$#]',
    b'backdoor|backdoor|^sh[$#]',
    b'backdoor|backdoor|^Microsoft Windows',
    b'db2|db2|.*SQLDB2RA',
    b'dell-openmanage|dell-openmanage|^\x4e\x00\x0d',
    b'finger|finger|^\r\n	Line	  User',
    b'finger|finger|Line	 User',
    b'finger|finger|Login name: ',
    b'finger|finger|Login.*Name.*TTY.*Idle',
    b'finger|finger|^No one logged on',
    b'finger|finger|^\r\nWelcome',
    b'finger|finger|^finger:',
    b'finger|finger|^must provide username',
    b'finger|finger|finger: GET: ',
    b'ftp|ftp|^220.*\n331',
    b'ftp|ftp|^220.*\n530',
    b'ftp|ftp|^220.*FTP',
    b'ftp|ftp|^220 .* Microsoft .* FTP',
    b'ftp|ftp|^220 Inactivity timer',
    b'ftp|ftp|^220 .* UserGate',
    b'ftp|ftp|^220.*FileZilla Server',
    b'ldap|ldap|^\x30\x0c\x02\x01\x01\x61',
    b'ldap|ldap|^\x30\x32\x02\x01',
    b'ldap|ldap|^\x30\x33\x02\x01',
    b'ldap|ldap|^\x30\x38\x02\x01',
    b'ldap|ldap|^\x30\x84',
    b'ldap|ldap|^\x30\x45',
    b'ldp|ldp|^\x00\x01\x00.*?\r\n\r\n$',
    b'rdp|rdp|^\x03\x00\x00\x0b',
    b'rdp|rdp|^\x03\x00\x00\x11',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
    b'rdp|rdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
    b'rdp|rdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
    b'rdp|rdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
    b'rdp|rdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    b'rdp-proxy|rdp-proxy|^nmproxy: Procotol byte is not 8\n$',
    b'msrpc|msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    b'msrpc|msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    b'mssql|mssql|^\x05\x6e\x00',
    b'mssql|mssql|^\x04\x01',
    b'mssql|mysql|;MSSQLSERVER;',
    b'mysql|mysql|mysql_native_password',
    b'mysql|mysql|^\x19\x00\x00\x00\x0a',
    b'mysql|mysql|^\x2c\x00\x00\x00\x0a',
    b'mysql|mysql|hhost \'',
    b'mysql|mysql|khost \'',
    b'mysql|mysql|mysqladmin',
    b'mysql|mysql|whost \'',
    b'mysql|mysql|^[.*]\x00\x00\x00\n.*?\x00',
    b'mysql-secured|mysql|this MySQL server',
    b'mysql-secured|MariaDB|MariaDB server',
    b'mysql-secured|mysql-secured|\x00\x00\x00\xffj\x04Host',
    b'db2jds|db2jds|^N\x00',
    b'nagiosd|nagiosd|Sorry, you \(.*are not among the allowed hosts...',
    b'nessus|nessus|< NTP 1.2 >\x0aUser:',
    b'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
    b'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
    b'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    b'oracle-https|^220- ora',
    b'rmi|rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
    b'rmi|rmi|^\x4e\x00\x09',
    b'postgresql|postgres|Invalid packet length',
    b'postgresql|postgres|^EFATAL',
    b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    b'rpc|rpc|\x01\x86\xa0',
    b'rpc|rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
    b'rpc|rpc|^\x80\x00\x00',
    b'rsync|rsync|^@RSYNCD:',
    b'smux|smux|^\x41\x01\x02\x00',
    b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
    b'snmp|snmp|\x41\x01\x02',
    b'socks|socks|^\x05[\x00-\x08]\x00',
    b'ssl|ssl|^..\x04\0.\0\x02',
    b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
    b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
    b'ssl|ssl|SSL.*GET_CLIENT_HELLO',
    b'ssl|ssl|^-ERR .*tls_start_servertls',
    b'ssl|ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
    b'ssl|ssl|^\x16\x03\0..\x02\0\0F\x03\0',
    b'ssl|ssl|^\x15\x03\0\0\x02\x02\.*',
    b'ssl|ssl|^\x16\x03\x01..\x02...\x03\x01',
    b'ssl|ssl|^\x16\x03\0..\x02...\x03\0',
    b'sybase|sybase|^\x04\x01\x00',
    b'telnet|telnet|Telnet',
    b'telnet|telnet|^\xff[\xfa-\xff]',
    b'telnet|telnet|^\r\n%connection closed by remote host!\x00$',
    b'rlogin|rlogin|login: ',
    b'rlogin|rlogin|rlogind: ',
    b'rlogin|rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
    b'tftp|tftp|^\x00[\x03\x05]\x00',
    b'uucp|uucp|^login: password: ',
    b'vnc|vnc|^RFB',
    b'imap|imap|^\* OK.*?IMAP',
    b'pop|pop|^\+OK.*?',
    b'smtp|smtp|^220.*?SMTP',
    b'smtp|smtp|^554 SMTP',
    b'ftp|ftp|^220-',
    b'ftp|ftp|^220.*?FTP',
    b'ftp|ftp|^220.*?FileZilla',
    b'ssh|ssh|^SSH-',
    b'ssh|ssh|connection refused by remote host.',
    b'rtsp|rtsp|^RTSP/',
    b'sip|sip|^SIP/',
    b'nntp|nntp|^200 NNTP',
    b'sccp|sccp|^\x01\x00\x00\x00$',
    b'webmin|webmin|.*MiniServ',
    b'webmin|webmin|^0\.0\.0\.0:.*:[0-9]',
    b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
    b'smb|smb|^\x83\x00\x00\x01\x8f',
    b'mongodb|mongodb|MongoDB',
    b'Rsync|Rsync|@RSYNCD:',
    b'Squid|Squid|X-Squid-Error',
    b'mssql|Mssql|MSSQLSERVER',
    b'Vmware|Vmware|VMware',
    b'iscsi|iscsi|\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'redis|redis|^-ERR unknown command',
    b'redis|redis|^-ERR wrong number of arguments',
    b'redis|redis|^-DENIED Redis is running',
    b'memcached|memcached|^ERROR\r\n',
    b'websocket|websocket|Server: WebSocket',
    b'https|https|Instead use the HTTPS scheme to access'
    b'https|https|HTTPS port',
    b'https|https|Location: https',
    b'SVN|SVN|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
    b'dubbo|dubbo|^Unsupported command',
    b'http|elasticsearch|cluster_name.*elasticsearch',
    b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
)


def get_server(port):
    SERVER = {
        'FTP': '21',
        'SSH': '22',
        'Telnet': '23',
        'SMTP': '25',
        'DNS': '53',
        'DHCP': '68',
        'HTTP': '80',
        'TFTP': '69',
        'HTTP': '8080',
        'POP3': '995',
        'POP3': '110',
        'NetBIOS': '139',
        'IMAP': '143',
        'HTTPS': '443',
        'SNMP': '161',
        'LDAP': '489',
        'SMB': '445',
        'SMTPS': '465',
        'Linux R RPE': '512',
        'Linux R RLT': '513',
        'Linux R cmd': '514',
        'Rsync': '1873',
        'IMAPS': '993',
        'Proxy': '1080',
        'JavaRMI': '10990',
        'Oracle EMCTL': '1158',
        'Lotus': '1352',
        'MSSQL': '1433',
        'MSSQL Monitor': '1434',
        'Oracle': '1521',
        'PPTP': '1723',
        'cPanel admin panel/CentOS web panel': '2082',
        'CPanel admin panel/CentOS web panel': '2083',
        'Oracle XDB FTP': '2100',
        'Zookeeper': '2181',
        'DA admin panel': '2222',
        'Docker': '2375',
        'Zebra': '2604',
        'Gitea Web': '3000',
        'Squid Proxy': '3128',
        'MySQL/MariaDB': '3306',
        'Kangle admin panel': '3312',
        'RDP': '3389',
        'SVN': '3690',
        'Rundeck': '4440',
        'GlassFish': '4848',
        'SysBase/DB2': '5000',
        'PostgreSql': '5432',
        'PcAnywhere': '5632',
        'VNC': '5900',
        'TeamViewer': '5938',
        'CouchDB': '5984',
        'varnish': '6082',
        'Redis': '6379',
        'Aria2': '6800',
        'Weblogic': '9001',
        'Kloxo admin panel': '7778',
        'Zabbix': '8069',
        'RouterOS/Winbox': '8291',
        'BT/宝塔面板': '8888',
        'WebSphere': '9090',
        'Elasticsearch': '9300',
        'Virtualmin/Webmin': '10000',
        'Zabbix agent': '10050',
        'Zabbix server': '10051',
        'Memcached': '11211',
        'FileZilla Manager': '14147',
        'MongoDB': '27017',
        'MongoDB': '28017',
        'SAP NetWeaver': '50000',
        'Hadoop': '50070',
        'hdfs':'9000',
    }
    for k, v in SERVER.items():
        if v == port:
            return k  # 只返回服务名，不包含端口号
    return 'Unknown'  # 只返回未知标记，不包含端口号


# 修改扫描端口范围，分为三类：常用端口、系统端口和高位端口
PORTS = [
    # 常用服务端口
    21, 22, 23, 25, 53, 69, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 110, 111, 135, 139, 143, 
    161, 389, 443, 445, 465, 489, 512, 513, 514, 873, 993, 995, 1080, 1158, 1433, 1434, 1521, 
    1723, 2082, 2083, 2181, 2222, 2375, 2604, 3000, 3128, 3306, 3312, 3389, 3690, 4440, 4848,
    5000, 5432, 5632, 5900, 5938, 5984, 6082, 6379, 6800, 7001, 7002, 7778, 8000, 8001, 8002,
    8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8069, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8888, 9000, 9001, 9002, 9003, 9004, 9005, 9090, 9200, 9300,
    10000, 10050, 10051, 11211, 27017, 27018, 27019, 50000, 50070,
    
    # 系统端口(1-1024)
    *range(1, 1025),
    
    # 高位常用端口
    *range(8000, 8090),  # 8000-8089
    *range(8440, 8450),  # 常见 Web 服务端口
    *range(9000, 9010),  # 常见 Web 服务端口
    *range(9090, 9100),  # 常见 Web 服务端口
]


PROBE = {
    'GET / HTTP/1.0\r\n\r\n'
}


class ScanPort():
    def __init__(self, ipaddr):
        self.ipaddr = ipaddr
        self.port = []
        self.out = []
        self.num = 0
        self.timeout = 2  # 增加超时时间到2秒

    def socket_scan(self, hosts):
        global PROBE
        socket.setdefaulttimeout(self.timeout)
        ip, port = hosts.split(':')
        try:
            # 移除25个端口的限制
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, int(port)))
            if result == 0:
                self.port.append(port)
                try:
                    for i in PROBE:
                        sock.sendall(i.encode())
                        response = sock.recv(256)
                        sock.close()
                        if response:
                            break
                    if response:
                        for pattern in SIGNS:
                            pattern = pattern.split(b'|')
                            if re.search(pattern[-1], response, re.IGNORECASE):
                                proto = '{}:{}'.format(pattern[1].decode(), port)
                                self.out.append(proto)
                                break
                except:
                    pass
        except (socket.timeout, ConnectionResetError):
            pass
        except:
            pass

    def run(self, ip):
        hosts = []
        global PORTS, THREADNUM
        # 使用set去重端口号
        unique_ports = list(set(PORTS))
        for i in unique_ports:
            hosts.append('{}:{}'.format(ip, i))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                executor.map(self.socket_scan, hosts)
        except EOFError:
            pass

    def pool(self):
        out = {}
        try:
            if (not parse.urlparse(self.ipaddr).path) and (parse.urlparse(self.ipaddr).path != '/'):
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
            else:
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
                self.ipaddr = re.sub('/\w+', '', self.ipaddr)
            if re.search('\d+\.\d+\.\d+\.\d+', self.ipaddr):
                ipaddr = self.ipaddr
            else:
                ipaddr = socket.gethostbyname(self.ipaddr)
            if ':' in ipaddr:
                ipaddr = re.sub(':\d+', '', ipaddr)
            self.run(ipaddr)
        except Exception as e:
            pass
        
        for i in self.out:
            service, port = i.split(':')
            out[port] = service
        
        for i in self.port:
            if i not in out:
                out[i] = get_server(i)
        
        if self.num == 0:
            return out
        else:
            return {'0': 'Portspoof'}


if __name__ == "__main__":
    print(ScanPort('127.0.0.1').pool())



