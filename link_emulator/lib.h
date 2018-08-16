#ifndef LIB
#define LIB

typedef struct {
    int len;
    char payload[1400];
} msg;

typedef struct {
	char soh; // start of header
	char len; // length(mini_kermit - 2)
	char seq; // sequence number
	char type; // S, F, D, Z, B, Y, N. E
	char data[250];
	unsigned short check; // control sum
	char mark; // end byte
} __attribute__((packed)) mini_kermit;

typedef struct {
	char maxl; // max data length
	char time; // for timeout
	char npad; // no of padding bytes
	char padc; // character used for padding
	char eol; // character used for mark
	char qctl;
	char qbin;
	char chkt;
	char rept;
	char capa;
	char r;
} __attribute__((packed)) send_init_data;

void init(char* remote, int remote_port);
void set_local_port(int port);
void set_remote(char* ip, int port);
int send_message(const msg* m);
int recv_message(msg* r);
msg* receive_message_timeout(int timeout); //timeout in milliseconds
unsigned short crc16_ccitt(const void *buf, int len);

// msg cu payload o structura mini kermit
msg* create_msg_mini_kermit(int seq, char type, void* data, int data_len, char eol);
// structura mini kermit din mesajul dat ca parametru
mini_kermit* get_mini_kermit(msg* message);
// 1 daca suma din pachet coincide cu cea calculata
int check_packet_sum(mini_kermit* packet, send_init_data* settings);
// 1 daca secventa din pachet coincide cu cea data ca parametru
int check_packet_seq(mini_kermit* packet, char seq);
// 1 daca tipul pachetului e acelasi cu cel dat ca parametru
int check_packet_type(mini_kermit* packet, char type);
// 1 daca tipul pachetului e unul din cele date ca parametru
int check_packet_types(mini_kermit* packet, const char* types);

#endif
