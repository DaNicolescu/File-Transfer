// Nicolescu Daniel-Marian
// 324CB
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "lib.h"

#define HOST "127.0.0.1"
#define PORT 10001

// Creeaza campul data folosit la Send-Init. Structura e folosita in restul
// programului pentru a pastra parametrii receiver-ului.
send_init_data* receiver_settings(char maxl, char time, char npad, char padc, char eol) {
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

// Creeaza un mesaj de tip ACK pentru Send-Init
msg* ack_init_packet(send_init_data* settings) {
    return create_msg_mini_kermit(0, 'Y', (void*) settings, sizeof(send_init_data), settings->eol);
}

// Creeaza un mesaj de tip ACK
msg* ack_packet(int seq, char eol) {
	return create_msg_mini_kermit(seq, 'Y', NULL, 0, eol);
}

// Creeaza un mesaj de tip NAK
msg* nak_packet(int seq, char eol) {
	return create_msg_mini_kermit(seq, 'N', NULL, 0, eol);
}

// Intoarce mesajul primit de la sender si retrimite ultimul pachet trimis de
// receiver in caz de timeout. In cazul in care receiver nu a trimis pachete
// pana acum, asteapta de maxim 3 * 5s pentru un pachet de la sender.
// Functia e folosita de receive_and_check.
msg* receive(msg* last_sent_packet, send_init_data* settings) {
	msg* received_message;
	int i = 0;

	// Daca receiver-ul nu a mai trimis pachete pana acum
    if(last_sent_packet == NULL) {
    	received_message = receive_message_timeout(((int) (settings->time)) * 1000 * 3);
    // Altfel asteapta maxim 5 secunde, apoi retrimite ultimul ACK/NAK
    } else {
	    for(i = 0; i < 3; i++) {
	    	received_message = receive_message_timeout(((int) (settings->time)) * 1000);

	    	if(received_message != NULL) {
	    		break;
	    	}

	    	// resends the last packet in case of timeout
	    	if(i < 2) {
	    		printf("[receiver] timeout\n");
	    		send_message(last_sent_packet);
	    	}
	    }
    }

    return received_message;
}

// Intoarce mesajul primit de la sender prin efect lateral in packet, precum si ultimul
// pachet trimis de receiver in last_sent_packet. Functia efectuaza si verificarea pachetului
// primit. Parametrul types contine tipurile de pachet pentru care se efectueaza verificarea.
int receive_and_check(mini_kermit** packet, msg** last_sent_packet, send_init_data* settings,
 const char* types, int seq) {
	msg* r;
	msg* packet_to_send = NULL;

	while(1) {
		// Intoarce mesajul de la sender
    	r = receive(*last_sent_packet, settings);
    	
    	// Daca nu a primit nimic
    	if(r == NULL) {
    		printf("[receiver] closed\n");
    		return 0;
    	}

    	if(*packet != NULL) {
    		free(*packet);
    		*packet = NULL;
    	}

    	// Transforma mesajul de tip msg in pachet de tip mini_kermit
        *packet = get_mini_kermit(r);

        free(r);
        r = NULL;

        // Daca pachetul este corupt, sau nu este cel corect, sau nu are unul
        // din tipurile din types
        if(!check_packet_sum(*packet, settings) || !check_packet_types(*packet, types) ||
         !check_packet_seq(*packet, seq)) {

         	printf("[receiver] Got wrong/corrupt msg payload\n");

         	if(packet_to_send != NULL) {
         		free(packet_to_send);
         		packet_to_send = NULL;
         	}

         	// Trimite NAK
         	packet_to_send = nak_packet(seq, settings->eol);
			send_message(packet_to_send);

			if(*last_sent_packet != NULL) {
				free(*last_sent_packet);
				*last_sent_packet = NULL;
			}

			// Actualizeaza ultimul pachet trimis de receiver si asteapta din nou
			// pachet de la sender.
			*last_sent_packet = packet_to_send;
			packet_to_send = NULL;
			continue;            
        }

        break;
    }
    printf("[receiver] Got msg with payload: %c\n", (*packet)->type);

    return 1;
}

// Eliberare memorie
void free_all(msg** last_sent_packet, mini_kermit** packet, send_init_data** settings) {
	if(*last_sent_packet != NULL) {
		free(*last_sent_packet);
		*last_sent_packet = NULL;
	}

	if(*packet != NULL) {
		free(*packet);
		*packet = NULL;
	}

	if(*settings != NULL) {
		free(*settings);
		*settings = NULL;
	}
}

int main(int argc, char** argv) {
	// Ultimul pachet trimis de receiver
    msg* last_sent_packet = NULL;
    // Pachetul ce urmeaza a fi trimis de receiver
    msg* packet_to_send = NULL;
    int seq = 0;
    // Pachet primit de la sender
    mini_kermit* packet = NULL;
    char* folder_name = NULL;
    int fd;
    int written_data_len = 0;
    int len;
    send_init_data* settings = receiver_settings(250, 5, 0, 0, 0x0D);


    init(HOST, PORT);

    // Primire pachet Send-Init
    if(!receive_and_check(&packet, &last_sent_packet, settings, "S", seq)) {
    	free_all(&last_sent_packet, &packet, &settings);
    	return 1;
    }
    
    free(packet);
    packet = NULL;
    free(last_sent_packet);
    last_sent_packet = NULL;

    // Trimitere ACK si actualizare ultimul pachet trimis
    packet_to_send = ack_init_packet(settings);
    send_message(packet_to_send);
    last_sent_packet = packet_to_send;

    // Primire pachete File Header, Date, EOF, EOT
    while(1) {
    	seq = (seq + 1) % 64;

    	folder_name = calloc(50, sizeof(char));
    	strcpy(folder_name, "recv_");

    	// Primire pachet File Header sau EOT
    	if(!receive_and_check(&packet, &last_sent_packet, settings, "FB", seq)) {
    		free_all(&last_sent_packet, &packet, &settings);
    		free(folder_name);
    		return 1;
    	}

    	// Daca pachetul e EOT iese din While
	    if(check_packet_type(packet, 'B')) {
	    	free(folder_name);
	    	folder_name = NULL;
	    	break;
	    }

	    // Creeaza fisier
	    strcat(folder_name, packet->data);
	    fd = creat(folder_name, S_IRWXG | S_IRWXU);

	    free(folder_name);
	    folder_name = NULL;

	    if(fd < 0) {
	    	free_all(&last_sent_packet, &packet, &settings);
	    	return 1;
	    }

	    free(last_sent_packet);
	    last_sent_packet = NULL;

	    // Trimitere ACK pentru File Header si actualizare ultimul pachet trimis
	    packet_to_send = ack_packet(seq, settings->eol);
    	send_message(packet_to_send);
    	last_sent_packet = packet_to_send;

    	// Primire pachete Date sau pachet EOF
    	written_data_len = 0;

    	do {
    		seq = (seq + 1) % 64;

    		free(packet);
    		packet = NULL;

    		// Primire pachet (Date sau EOF)
    		if(!receive_and_check(&packet, &last_sent_packet, settings, "DZ", seq)) {
    			free_all(&last_sent_packet, &packet, &settings);
    			return 1;
    		}

    		// Daca pachetul e de tip Date
		    if(check_packet_type(packet, 'D')) {
		    	// Scrie in fisier
		    	len = (packet->len & 0xff) - 5;
		    	written_data_len = write(fd, (void*) (packet->data), len);

		    	if(written_data_len < len) {
		    		free_all(&last_sent_packet, &packet, &settings);
		    		return 1;
		    	}
		    }
		    
		    free(last_sent_packet);
		    last_sent_packet = NULL;

		    // Trimite ACK pentru Date/EOF
		    packet_to_send = ack_packet(seq, settings->eol);
		    send_message(packet_to_send);
		    last_sent_packet = packet_to_send;

	    } while(check_packet_type(packet, 'D'));

	    free(packet);
	    packet = NULL;
	    close(fd);	    	

    }

    // Trimite ACK pentru pachet EOT
    free(last_sent_packet);
    last_sent_packet = NULL;

    packet_to_send = ack_packet(seq, settings->eol);
    send_message(packet_to_send);
    last_sent_packet = packet_to_send;

	printf("[receiver] Got msg with payload: %c\n", packet->type);
	printf("[receiver] closed\n");

	free_all(&last_sent_packet, &packet, &settings);
    
	return 0;
}
