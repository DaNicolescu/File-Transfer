// Nicolescu Daniel-Marian
// 324CB
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "lib.h"

#define HOST "127.0.0.1"
#define PORT 10000

// Creeaza campul data folosit la Send-Init. Structura e folosita in restul
// programului pentru a pastra parametrii sender-ului.
send_init_data* sender_settings(char maxl, char time, char npad, char padc, char eol) {
    send_init_data* settings = malloc(sizeof(send_init_data));

    settings->maxl = maxl;
    settings->time = time;
    settings->npad = npad;
    settings->padc = padc;
    settings->eol = eol;
    settings->qctl = 0;
    settings->qbin = 0;
    settings->chkt = 0;
    settings->rept = 0;
    settings->capa = 0;
    settings->r = 0;

    return settings;
}

// Creeaza un mesaj ce are ca payload un pachet Send-Init
msg* init_packet(send_init_data* settings) {
    return create_msg_mini_kermit(0, 'S', (void*) settings, sizeof(send_init_data), settings->eol);
}

// Creeaza un mesaj ce are ca payload un pachet File Header
msg* file_header_packet(int seq, char* file_name, char eol) {
    return create_msg_mini_kermit(seq, 'F', (void*) file_name, strlen(file_name) + 1, eol);
}

// Creeaza un mesaj ce are ca payload un pachet Date
msg* data_packet(int seq, char* data, int data_len, char eol) {
    return create_msg_mini_kermit(seq, 'D', (void*) data, data_len, eol);
}

// Creeaza un mesaj ce are ca payload un pachet EOF
msg* eof_packet(int seq, char eol) {
    return create_msg_mini_kermit(seq, 'Z', NULL, 0, eol);
}

// Creeaza un mesaj ce are ca payload un pachet EOT
msg* eot_packet(int seq, char eol) {
    return create_msg_mini_kermit(seq, 'B', NULL, 0, eol);
}

// Transmite mesajul packet_to_send si asteapta ACK pentru el.
// Daca nu primeste raspuns in 5 secunde il retrimite. Trimiterea in caz
// de timeout se realizeaza de maxim 3 ori. In cazul in care primeste un 
// raspuns corupt sau NAK reseteaza contorul si retrimite mesajul de maxim 3 ori.
int transmit(msg* packet_to_send, send_init_data* settings, int seq) {
    int try = 0;
    msg* r;
    mini_kermit* received_packet;

    while(try < 3) {
    	// Trimite pachet
        send_message(packet_to_send);

        r = receive_message_timeout(((int) (settings->time)) * 1000);

        // Daca a primit pachet de la receiver
        if (r != NULL) {
            received_packet = get_mini_kermit(r);

            // Daca este corupt, sau nu are numarul de secventa
            // corect sau este NAK
            if(!check_packet_sum(received_packet, settings) || 
            	check_packet_type(received_packet, 'N') ||
             !check_packet_seq(received_packet, seq)) {

            	// Reseteaza contorul
                try = 0;
                printf("[sender] Got reply with corrupt/NAK payload\n");

                free(r);
                r = NULL;
                free(received_packet);

                continue;
            // Daca este ACK
            } else {
                printf("[sender] Got reply with payload: %c\n", received_packet->type);

                free(r);
                r = NULL;
                free(received_packet);

                break;
            }
        }

        if(try < 2) {
        	printf("[sender] timeout\n");
        }

        try++;
    }

    // Daca nu a primit raspuns
    if(try == 3) {
        printf("[sender] closed\n");
        return 0;
    }

    return 1;
}

// Eliberare de memorie
void free_all(msg** packet_to_send, send_init_data** settings, char** read_data) {
	if(*packet_to_send != NULL) {
		free(*packet_to_send);
		*packet_to_send = NULL;
	}

	if(*settings != NULL) {
		free(*settings);
		*settings = NULL;
	}

	if(*read_data != NULL) {
		free(*read_data);
		*read_data = NULL;
	}
}

int main(int argc, char** argv) {
	// mesaj ce contine pachetul ce trebuie trimis
    msg* packet_to_send;
    // setarile sender-ului
    send_init_data* settings = sender_settings(250, 5, 0, 0, 0x0D);
    int seq = 0;
    int fd;
    int i;
    int copied_text_len = 0;
    int max_len = (unsigned char) settings->maxl;
    char* read_data = malloc(max_len * sizeof(char));

    init(HOST, PORT);

    // Trimitere pachet Send-Init
    packet_to_send = init_packet(settings);

    if(!transmit(packet_to_send, settings, seq)) {
    	free_all(&packet_to_send, &settings, &read_data);
        return 1;
    }

    free(packet_to_send);
    packet_to_send = NULL;

    // Trimitere Fisiere
    for(i = 1; i < argc; i++) {
        seq = (seq + 1) % 64;

        // Deschidere fisier
        fd = open(argv[i], O_RDONLY);

        if(fd < 0) {
        	free_all(&packet_to_send, &settings, &read_data);
            return 1;
        }

        // Trimitere pachet File Header
        packet_to_send = file_header_packet(seq, argv[i], settings->eol);

        if(!transmit(packet_to_send, settings, seq)) {
        	free_all(&packet_to_send, &settings, &read_data);
            return 1;
        }

        free(packet_to_send);
        packet_to_send = NULL;

        // Trimitere pachete Date cat timp numarul de bytes cititi este egal cu
        // numarul maxim de bytes pe care ii poate citi
        do {
            seq = (seq + 1) % 64;

            // Citire din fisier
            copied_text_len = read(fd, (void*) read_data, max_len);

            if(copied_text_len == 0) {
                break;
            }

            if(copied_text_len < 0) {
            	free_all(&packet_to_send, &settings, &read_data);
                return 1;
            }

            // Trimitere pachet
            packet_to_send = data_packet(seq, read_data, copied_text_len, settings->eol);

            if(!transmit(packet_to_send, settings, seq)) {
            	free_all(&packet_to_send, &settings, &read_data);
                return 1;
            }

            free(packet_to_send);
            packet_to_send = NULL;

        } while(copied_text_len == max_len);

        // Trimitere pachet EOF
        seq = (seq + 1) % 64;

        packet_to_send = eof_packet(seq, settings->eol);

        if(!transmit(packet_to_send, settings, seq)) {
        	free_all(&packet_to_send, &settings, &read_data);
            return 1;
        }

        free(packet_to_send);
        packet_to_send = NULL;

        close(fd);

    }

    // Trimitere pachet EOT
    seq = (seq + 1) % 64;

    packet_to_send = eot_packet(seq, settings->eol);

    if(!transmit(packet_to_send, settings, seq)) {
    	free_all(&packet_to_send, &settings, &read_data);
        return 1;
    }

    free_all(&packet_to_send, &settings, &read_data);

    printf("[sender] closed\n");

    return 0;
}
