#include "lib.h"
#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

struct sockaddr_in addr_local, addr_remote;
int s;
struct pollfd fds[1];

static const unsigned short crc16tab[256]= {
	0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
	0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
	0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
	0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
	0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
	0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
	0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
	0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
	0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
	0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
	0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
	0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
	0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
	0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
	0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
	0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
	0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
	0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
	0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
	0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
	0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
	0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
	0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
	0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
	0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
	0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
	0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
	0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
	0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
	0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
	0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
	0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

void set_local_port(int port) {
    memset((char *) &addr_local, 0, sizeof (addr_local));
    addr_local.sin_family = AF_INET;
    addr_local.sin_port = htons(port);
    addr_local.sin_addr.s_addr = htonl(INADDR_ANY);
}

void set_remote(char* ip, int port) {
    memset((char *) &addr_remote, 0, sizeof (addr_remote));
    addr_remote.sin_family = AF_INET;
    addr_remote.sin_port = htons(port);
    if (inet_aton(ip, &addr_remote.sin_addr) == 0) {
        perror("inet_aton failed\n");
        exit(1);
    }
}

void init(char* remote, int REMOTE_PORT) {
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("Error creating socket");
        exit(1);
    }

    set_local_port(0);
    set_remote(remote, REMOTE_PORT);

    if (bind(s, (struct sockaddr*) &addr_local, sizeof (addr_local)) == -1) {
        perror("Failed to bind");
        exit(1);
    }

    fds[0].fd = s;
    fds[0].events = POLLIN;

    msg m;
    send_message(&m);
}

int send_message(const msg* m) {
    return sendto(s, m, sizeof (msg), 0, (struct sockaddr*) &addr_remote, sizeof (addr_remote));
}

msg* receive_message() {
    msg* ret = (msg*) malloc(sizeof (msg));
    if (recvfrom(s, ret, sizeof (msg), 0, NULL, NULL) == -1) {
        free(ret);
        return NULL;
    }
    return ret;
}

int recv_message(msg* ret) {
    return recvfrom(s, ret, sizeof (msg), 0, NULL, NULL);
}


//timeout in millis
msg* receive_message_timeout(int timeout) {
    int ret = poll(fds, 1, timeout);
    if (ret > 0) {
        if (fds[0].revents & POLLIN)
            return receive_message();
    }
    return NULL;
}

unsigned short crc16_ccitt(const void *buf, int len) {
    register int counter;
    register unsigned short crc = 0;
    for (counter = 0; counter < len; counter++)
        crc = (crc << 8) ^ crc16tab[((crc >> 8) ^ *(char *) buf++)&0x00FF];
    return crc;
}

// Creeaza o structura msg ce contine un pachet mini kermit
msg* create_msg_mini_kermit(int seq, char type, void* data, int data_len, char eol) {
    mini_kermit packet;
    msg* message = NULL;
    message = calloc(1, sizeof(msg));

    // Seteaza soh, len, seq si type
    packet.soh = 1;
    packet.len = data_len + 5;
    packet.seq = seq;
    packet.type = type;

    // Copiaza date in campul Data daca este necesar
    if(data != NULL) {
        memcpy(packet.data, data, data_len);    
    }
    
    // Calculeaza suma de control
    packet.check = crc16_ccitt((void*) (&packet), data_len + 4);
    // Seteaza soh
    packet.mark = eol;

    // Copiaza structura in payload-ul mesajului si ii seteaza lungimea
    memcpy(message->payload, &packet, data_len + 4);
    memcpy(message->payload + data_len + 4, &(packet.check), 3);
    message->len = data_len + 7;

    return message;
}

// Intoarce o structura mini kermit din mesajul dat ca parametru
mini_kermit* get_mini_kermit(msg* message) {
    mini_kermit* packet = calloc(1, sizeof(mini_kermit));

    memcpy(packet, message->payload, message->len - 3);
    memcpy(&(packet->check), message->payload + message->len - 3, 3);

    return packet;
}

// Intoarce 1 daca suma din pachet coincide cu cea calculata, 0 altfel
int check_packet_sum(mini_kermit* packet, send_init_data* settings) {
    int len = (packet->len & 0xff);
    int maxl = ((unsigned char) settings->maxl) + 7;
    
    if((len > maxl) || (len < 5) ||
        (packet->check != crc16_ccitt((void*) (packet), len - 1))) {
        return 0;
    }

    return 1;
}

// Intoarce 1 daca secventa pachetului coincide cu secventa data ca parametru,
// 0 altfel
int check_packet_seq(mini_kermit* packet, char seq) {
    if(packet->seq == seq) {
        return 1;
    }

    return 0;
}

// Intoarce 1 daca pachetul este de tipul type, 0 altfel
int check_packet_type(mini_kermit* packet, char type) {
    if(packet->type == type) {
        return 1;
    }

    return 0;
}

// Intoarce 1 daca pachetul are unul din tipurile date ca parametru, 0 altfel
int check_packet_types(mini_kermit* packet, const char* types) {
    int i;

    for(i = 0; i < strlen(types); i++) {
        if(packet->type == types[i]) {
            return 1;
        }
    }

    return 0;
}