/*
 * Sean Middleditch
 * sean@sourcemud.org
 *
 * The author or authors of this code dedicate any and all copyright interest
 * in this code to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and successors. We
 * intend this dedication to be an overt act of relinquishment in perpetuity of
 * all present and future rights to this code under copyright law.
 */

#if !defined(_WIN32)
#	if !defined(_BSD_SOURCE)
#		define _BSD_SOURCE
#	endif

#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <netdb.h>
#	include <poll.h>
#	include <unistd.h>
#   include <pthread.h>

#	define SOCKET int
#else
#	include <winsock2.h>
#	include <ws2tcpip.h>

#ifndef _UCRT
#	define snprintf _snprintf
#endif

#	define poll WSAPoll
#	define close closesocket
#	undef gai_strerror
#	define gai_strerror gai_strerrorA
#	if !defined(ECONNRESET)
#		define ECONNRESET WSAECONNRESET
#	endif
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>


#ifdef HAVE_ZLIB
#include "zlib.h"
#endif

#include "libtelnet.h"

#ifdef ENABLE_COLOR
# define COLOR_SERVER "\e[35m"
# define COLOR_CLIENT "\e[34m"
# define COLOR_BOLD "\e[1m"
# define COLOR_UNBOLD "\e[22m"
# define COLOR_NORMAL "\e[0m"
#else
# define COLOR_SERVER ""
# define COLOR_CLIENT ""
# define COLOR_BOLD ""
# define COLOR_UNBOLD ""
# define COLOR_NORMAL ""
#endif

# define EXEC_CLNUP 1
# define NO_EXEC_CLNUP 0
# define USECS 10000

struct conn_t {
	const char *name;
	SOCKET sock;
	telnet_t *telnet;
	struct conn_t *remote;
};

struct ticket_lock_t {
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    unsigned long queue_head;
    unsigned long queue_tail;
};

/*void ticket_lock_init(struct ticket_lock *ticket)
{
    ticket->cond = PTHREAD_COND_INITIALIZER;
    ticket->mutex = PTHREAD_MUTEX_INITIALIZER;
    ticket->queue_head = 0;
    ticket->queue_tail = 0;
}*/
#define TICKET_LOCK_INITIALIZER { PTHREAD_COND_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, 0, 0 }

void ticket_lock(struct ticket_lock_t *ticket)
{
    unsigned long queue_me;

    pthread_mutex_lock(&ticket->mutex);
    queue_me = ticket->queue_tail++;
    while (queue_me != ticket->queue_head)
    {
        pthread_cond_wait(&ticket->cond, &ticket->mutex);
    }
    pthread_mutex_unlock(&ticket->mutex);
}

void ticket_unlock(struct ticket_lock_t *ticket)
{
    pthread_mutex_lock(&ticket->mutex);
    ticket->queue_head++;
    pthread_cond_broadcast(&ticket->cond);
    pthread_mutex_unlock(&ticket->mutex);
}

static pthread_mutex_t mutex_thread_count = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_thread_count = PTHREAD_COND_INITIALIZER;
static int conn_thread_count = 0;

static const int THREAD_EXITED = 0;
static const int THREAD_CANCELLED = 1;
static const int THREAD_INITIALIZING = 2;
static const int THREAD_ERROR = 3;

static const char *get_cmd(unsigned char cmd) {
	static char buffer[4];

	switch (cmd) {
	case 255: return "IAC";
	case 254: return "DONT";
	case 253: return "DO";
	case 252: return "WONT";
	case 251: return "WILL";
	case 250: return "SB";
	case 249: return "GA";
	case 248: return "EL";
	case 247: return "EC";
	case 246: return "AYT";
	case 245: return "AO";
	case 244: return "IP";
	case 243: return "BREAK";
	case 242: return "DM";
	case 241: return "NOP";
	case 240: return "SE";
	case 239: return "EOR";
	case 238: return "ABORT";
	case 237: return "SUSP";
	case 236: return "xEOF";
	default:
		snprintf(buffer, sizeof(buffer), "%d", (int)cmd);
		return buffer;
	}
}

static const char *get_opt(unsigned char opt) {
	switch (opt) {
	case 0: return "BINARY";
	case 1: return "ECHO";
	case 2: return "RCP";
	case 3: return "SGA";
	case 4: return "NAMS";
	case 5: return "STATUS";
	case 6: return "TM";
	case 7: return "RCTE";
	case 8: return "NAOL";
	case 9: return "NAOP";
	case 10: return "NAOCRD";
	case 11: return "NAOHTS";
	case 12: return "NAOHTD";
	case 13: return "NAOFFD";
	case 14: return "NAOVTS";
	case 15: return "NAOVTD";
	case 16: return "NAOLFD";
	case 17: return "XASCII";
	case 18: return "LOGOUT";
	case 19: return "BM";
	case 20: return "DET";
	case 21: return "SUPDUP";
	case 22: return "SUPDUPOUTPUT";
	case 23: return "SNDLOC";
	case 24: return "TTYPE";
	case 25: return "EOR";
	case 26: return "TUID";
	case 27: return "OUTMRK";
	case 28: return "TTYLOC";
	case 29: return "3270REGIME";
	case 30: return "X3PAD";
	case 31: return "NAWS";
	case 32: return "TSPEED";
	case 33: return "LFLOW";
	case 34: return "LINEMODE";
	case 35: return "XDISPLOC";
	case 36: return "ENVIRON";
	case 37: return "AUTHENTICATION";
	case 38: return "ENCRYPT";
	case 39: return "NEW-ENVIRON";
	case 70: return "MSSP";
	case 85: return "COMPRESS";
	case 86: return "COMPRESS2";
	case 93: return "ZMP";
	case 255: return "EXOPL";
	default: return "unknown";
	}
}

static void print_buffer(const char *buffer, size_t size) {
	size_t i;

	printf("%.*s [", (int)size, buffer);
	for (i = 0; i != size; ++i) {
		printf("<" COLOR_BOLD "0x%02X" COLOR_UNBOLD ">", (unsigned char)buffer[i]);
		if(buffer[i] == '\n') printf("%c", '\n');
	}
	printf("]");
}

static void _send(SOCKET sock, const char *buffer, size_t size) {
	int rs;

	/* send data */
	while (size > 0) {
		if ((rs = send(sock, buffer, (int)size, 0)) == -1) {
			if (errno != EINTR && errno != ECONNRESET) {
				fprintf(stderr, "send() failed: %s\n", strerror(errno));
				exit(1);
			} else {
				return;
			}
		} else if (rs == 0) {
			fprintf(stderr, "send() unexpectedly returned 0\n");
			exit(1);
		}

		/* update pointer and size to see if we've got more to send */
		buffer += rs;
		size -= rs;
	}
}

static void _event_handler(telnet_t *telnet, telnet_event_t *ev,
		void *user_data) {
	struct conn_t *conn = (struct conn_t*)user_data;

	(void)telnet;

	switch (ev->type) {
	/* data received */
	case TELNET_EV_DATA:
		printf("%s DATA: ", conn->name);
		print_buffer(ev->data.buffer, ev->data.size);
		printf(COLOR_NORMAL "\n");

		telnet_send(conn->remote->telnet, ev->data.buffer, ev->data.size);
		break;
	/* data must be sent */
	case TELNET_EV_SEND:
		/* DONT SPAM
		printf("%s SEND: ", conn->name);
		print_buffer(ev->buffer, ev->size);
		printf(COLOR_BOLD "\n");
		*/

		_send(conn->sock, ev->data.buffer, ev->data.size);
		break;
	/* IAC command */
	case TELNET_EV_IAC:
		printf("%s IAC %s" COLOR_NORMAL "\n", conn->name,
				get_cmd(ev->iac.cmd));

		telnet_iac(conn->remote->telnet, ev->iac.cmd);
		break;
	/* negotiation, WILL */
	case TELNET_EV_WILL:
		printf("%s IAC WILL %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->neg.telopt, get_opt(ev->neg.telopt));
		telnet_negotiate(conn->remote->telnet, TELNET_WILL,
				ev->neg.telopt);
		break;
	/* negotiation, WONT */
	case TELNET_EV_WONT:
		printf("%s IAC WONT %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->neg.telopt, get_opt(ev->neg.telopt));
		telnet_negotiate(conn->remote->telnet, TELNET_WONT,
				ev->neg.telopt);
		break;
	/* negotiation, DO */
	case TELNET_EV_DO:
		printf("%s IAC DO %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->neg.telopt, get_opt(ev->neg.telopt));
		telnet_negotiate(conn->remote->telnet, TELNET_DO,
				ev->neg.telopt);
		break;
	case TELNET_EV_DONT:
		printf("%s IAC DONT %d (%s)" COLOR_NORMAL "\n", conn->name,
				(int)ev->neg.telopt, get_opt(ev->neg.telopt));
		telnet_negotiate(conn->remote->telnet, TELNET_DONT,
				ev->neg.telopt);
		break;
	/* generic subnegotiation */
	case TELNET_EV_SUBNEGOTIATION:
		printf("%s SUB %d (%s)", conn->name, (int)ev->sub.telopt,
				get_opt(ev->sub.telopt));
		if (ev->sub.size > 0) {
			printf(" [%ld bytes]: ", (long)ev->sub.size);
			print_buffer(ev->sub.buffer, ev->sub.size);
		}
		printf(COLOR_NORMAL "\n");

		/* forward */
		telnet_subnegotiation(conn->remote->telnet, ev->sub.telopt,
				ev->sub.buffer, ev->sub.size);
		break;
	/* ZMP command */
	case TELNET_EV_ZMP:
		if (ev->zmp.argc != 0) {
			size_t i;
			printf("%s ZMP [%ld params]", conn->name, (long)ev->zmp.argc);
			for (i = 0; i != ev->zmp.argc; ++i) {
				printf(" \"");
				print_buffer(ev->zmp.argv[i], strlen(ev->zmp.argv[i]));
				printf("\"");
			}
			printf(COLOR_NORMAL "\n");
		}
		break;
	/* TERMINAL-TYPE command */
	case TELNET_EV_TTYPE:
		printf("%s TTYPE %s %s", conn->name, ev->ttype.cmd ? "SEND" : "IS",
				ev->ttype.name ? ev->ttype.name : "");
		break;
	/* ENVIRON/NEW-ENVIRON commands */
	case TELNET_EV_ENVIRON: {
		size_t i;
		printf("%s ENVIRON (%s) [%ld parts]", conn->name, ev->environ.cmd == TELNET_ENVIRON_IS ? "IS" : ev->environ.cmd == TELNET_ENVIRON_SEND ? "SEND" : "INFO", (long)ev->environ.size);
		for (i = 0; i != ev->environ.size; ++i) {
			printf(" %s \"", ev->environ.values[i].type == TELNET_ENVIRON_VAR ? "VAR" : "USERVAR");
			if (ev->environ.values[i].var != 0) {
				print_buffer(ev->environ.values[i].var, strlen(ev->environ.values[i].var));
			}
			if (ev->environ.cmd != TELNET_ENVIRON_SEND) {
				printf("\"=\"");
				if (ev->environ.values[i].value != 0) {
					print_buffer(ev->environ.values[i].value, strlen(ev->environ.values[i].value));
				}
				printf("\"");
			}
		}
		printf(COLOR_NORMAL "\n");
		break;
	}
	case TELNET_EV_MSSP: {
		size_t i;
		printf("%s MSSP [%ld parts]", conn->name, (long)ev->mssp.size);
		for (i = 0; i != ev->mssp.size; ++i) {
			printf(" \"");
			print_buffer(ev->mssp.values[i].var, strlen(ev->mssp.values[i].var));
			printf("\"=\"");
			print_buffer(ev->mssp.values[i].value, strlen(ev->mssp.values[i].value));
			printf("\"");
		}
		printf(COLOR_NORMAL "\n");
		break;
	}
	/* compression notification */
	case TELNET_EV_COMPRESS:
		printf("%s COMPRESSION %s" COLOR_NORMAL "\n", conn->name,
				ev->compress.state ? "ON" : "OFF");
		break;
	/* warning */
	case TELNET_EV_WARNING:
		printf("%s WARNING: %s in %s,%d: %s" COLOR_NORMAL "\n", conn->name,
				ev->error.func, ev->error.file, ev->error.line, ev->error.msg);
		break;
	/* error */
	case TELNET_EV_ERROR:
		printf("%s ERROR: %s in %s,%d: %s" COLOR_NORMAL "\n", conn->name,
				ev->error.func, ev->error.file, ev->error.line, ev->error.msg);
		exit(1);
	}
}

struct threadlist{
    struct threadlist *next;
    struct threadlist *prev;
    pthread_t thread_id;
    SOCKET *listen_sock;
};

void delete_threadlist_element(struct threadlist *item)
{
    struct threadlist *cache = NULL;
    if(item->prev != NULL){
        item->prev->next = item->next;
    }
    if (item->next != NULL) {
        item->next->prev = item->prev;
    }
    
    free(item);
}


struct cleanup_handler_args {
    pthread_t thread_self;
    int *thread_status;
    struct threadlist* threadlist_element;
    pthread_mutex_t *mutex_threadlist;
    struct ticket_lock_t * ticket;

    //only used for thread_gen_cleanup
    struct conn_t *server;
    struct conn_t *client;
    SOCKET *listen_sock;
};

void* connection_cleanup_handler (void* args){
    struct cleanup_handler_args *params = (struct cleanup_handler_args*)args;
    int rc = 0;
    struct threadlist *iter = params->threadlist_element;
    struct threadlist *prev = NULL;
    

    if(*(params->thread_status) == THREAD_EXITED || *(params->thread_status) == THREAD_ERROR
            || *(params->thread_status) == THREAD_INITIALIZING )
    {
        ticket_lock(params->ticket);
        delete_threadlist_element(params->threadlist_element);
        ticket_unlock(params->ticket);
    }
    
    if( *(params->thread_status) != THREAD_INITIALIZING ){
        
        /* clean up */
    	telnet_free(params->server->telnet);
    	telnet_free(params->client->telnet);
    	close(params->server->sock);
    	close(params->client->sock);
    }

    return params->thread_status;
}

struct thread_arguments {
    char **argv;
    struct threadlist* threadlist_element;
    pthread_cond_t* cond_threadlist;
    struct ticket_lock_t * ticket;
};

void* run_connection(void* args){
    struct thread_arguments *params = (struct thread_arguments *)args;
    int rc = 0;
    char buffer[512];
    short listen_port;
    SOCKET listen_sock;
    int rs;
    struct sockaddr_in addr;
    socklen_t addrlen;
    struct pollfd pfd[2];
    struct conn_t server;
    struct conn_t client;
    struct addrinfo *ai;
    struct addrinfo hints;
    struct cleanup_handler_args cleanup_args;
    cleanup_args.threadlist_element = params->threadlist_element;
    cleanup_args.thread_status = &THREAD_INITIALIZING;
    cleanup_args.thread_self = pthread_self();
    cleanup_args.server = &server;
    cleanup_args.client = &client;
    cleanup_args.listen_sock = &listen_sock;
    cleanup_args.ticket = params->ticket;
    pthread_cleanup_push(connection_cleanup_handler, &cleanup_args);
    
    ticket_lock(params->ticket);
    params->threadlist_element->listen_sock = &listen_sock;
    ticket_unlock(params->ticket);
    
    
    /* initialize Winsock */
    //re-add for final version


    
	/* parse listening port */
	listen_port = (short)strtol(params->argv[3], 0, 10);

	/* create listening socket */
	if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        pthread_exit(cleanup_args.thread_status);
	}

	/* reuse address option */
	rs = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&rs, sizeof(rs));

	/* bind to listening addr/port */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(listen_port);
	if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		close(listen_sock);
        pthread_exit(cleanup_args.thread_status);
	}

	printf("LISTENING ON PORT %d\n", listen_port);

	/* wait for client */
	if (listen(listen_sock, 1) == -1) {
		fprintf(stderr, "listen() failed: %s\n", strerror(errno));
		close(listen_sock);
        pthread_exit(cleanup_args.thread_status);
	}
	addrlen = sizeof(addr);
	if ((client.sock = accept(listen_sock, (struct sockaddr *)&addr,
			&addrlen)) == -1) {
		fprintf(stderr, "accept() interrupted: %s\n", strerror(errno));
		close(listen_sock);
                pthread_exit(cleanup_args.thread_status);
	}

	printf("CLIENT CONNECTION RECEIVED\n");

	/* stop listening now that we have a client */
	close(listen_sock);

	/* look up server host */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((rs = getaddrinfo(params->argv[1], params->argv[2], &hints, &ai)) != 0) {
		fprintf(stderr, "getaddrinfo() failed for %s: %s\n", params->argv[1],
				gai_strerror(rs));
		close(client.sock);
        pthread_exit(cleanup_args.thread_status);
	}

	/* create server socket */
	if ((server.sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		close(server.sock);
        pthread_exit(cleanup_args.thread_status);
	}

	/* bind server socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (bind(server.sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		close(server.sock);
        pthread_exit(cleanup_args.thread_status);
	}

	/* connect */
	if (connect(server.sock, ai->ai_addr, (int)ai->ai_addrlen) == -1) {
		fprintf(stderr, "server() failed: %s\n", strerror(errno));
		close(server.sock);
        pthread_exit(cleanup_args.thread_status);
	}

	/* free address lookup info */
	freeaddrinfo(ai);

	printf("SERVER CONNECTION ESTABLISHED\n");

	/* initialize connection structs */
	server.name = COLOR_SERVER "SERVER";
	server.remote = &client;
	client.name = COLOR_CLIENT "CLIENT";
	client.remote = &server;

	/* initialize telnet boxes */
	server.telnet = telnet_init(0, _event_handler, TELNET_FLAG_PROXY,
			&server);
	client.telnet = telnet_init(0, _event_handler, TELNET_FLAG_PROXY,
			&client);

	/* initialize poll descriptors */
	memset(pfd, 0, sizeof(pfd));
	pfd[0].fd = server.sock;
	pfd[0].events = POLLIN;
	pfd[1].fd = client.sock;
	pfd[1].events = POLLIN;

    cleanup_args.thread_status = &THREAD_CANCELLED;
    if(rc = pthread_cond_signal(params->cond_threadlist)){
        fprintf(stderr, "pthread_cond_signal failed: %s\n", strerror(errno));
        pthread_exit(cleanup_args.thread_status);
    }
    
    free(params);


    /* loop while both connections are open */
    while (poll(pfd, 2, -1) != -1) {
            /* read from server */
            if (pfd[0].revents & POLLIN) {
                    if ((rs = recv(server.sock, buffer, sizeof(buffer), 0)) > 0) {
                            telnet_recv(server.telnet, buffer, rs);
                    } else if (rs == 0) {
                            printf("%s DISCONNECTED" COLOR_NORMAL "\n", server.name);
                            break;
                    } else {
                            if (errno != EINTR && errno != ECONNRESET) {
                                    fprintf(stderr, "recv(server) failed: %s\n",
                                                    strerror(errno));
                                    cleanup_args.thread_status = &THREAD_ERROR;
                                    pthread_exit(cleanup_args.thread_status);
                            }
                    }
            }

            /* read from client */
            if (pfd[1].revents & POLLIN) {
                    if ((rs = recv(client.sock, buffer, sizeof(buffer), 0)) > 0) {
                            telnet_recv(client.telnet, buffer, rs);
                    } else if (rs == 0) {
                            printf("%s DISCONNECTED" COLOR_NORMAL "\n", client.name);
                            break;
                    } else {
                            if (errno != EINTR && errno != ECONNRESET) {
                                    fprintf(stderr, "recv(server) failed: %s\n",
                                                    strerror(errno));
                                    cleanup_args.thread_status = &THREAD_ERROR;
                                    pthread_exit(cleanup_args.thread_status);
                            }
                    }
            }
    }
    
    /* all done */
    printf("BOTH CONNECTIONS CLOSED\n");

    /* exit thread and call cleanup handler*/
    cleanup_args.thread_status = &THREAD_EXITED;
    pthread_exit(cleanup_args.thread_status);
    pthread_cleanup_pop(EXEC_CLNUP);

    /* will never reach this */
    return 0;
}

void* thread_generation_cleanup(void* args){
    struct cleanup_handler_args *params = (struct cleanup_handler_args*)args;
    struct threadlist *connection_threads = params->threadlist_element;
    struct threadlist *to_delete = NULL;
    int rc = 0;
    
    if(rc = pthread_mutex_unlock(params->mutex_threadlist)){
                fprintf(stderr, "mutex_threadlist unlock failed in "
                "thread generation cleanup: %s\n", strerror(errno));
                pthread_exit(NULL);
        }
    
    
        
    //cancel all connection threads
    while(connection_threads->next != NULL){
        printf("blubb\n");
        ticket_lock(params->ticket);
        printf("grap\n");
        if(rc = pthread_cancel(connection_threads->thread_id)){
            fprintf(stderr, "cancelling thread failed in "
            "thread generation cleanup: %s (%d)\n", strerror(errno), rc);
        }
        
        ticket_unlock(params->ticket);
        if(rc = pthread_join(connection_threads->thread_id, NULL)){
            fprintf(stderr, "waiting for thread failed in "
            "thread generation cleanup: %s (%d)\n", strerror(rc), rc);
        }
        ticket_lock(params->ticket);
        to_delete = connection_threads;
        connection_threads = connection_threads->next;
        delete_threadlist_element(to_delete);
        ticket_unlock(params->ticket);
    }
    
    printf("trying to shutdown socket\n");
    if(rc = shutdown(*(connection_threads->listen_sock), SHUT_RDWR)){
        fprintf(stderr, "shutting down socket failed in "
        "thread generation cleanup: %s (%d)\n", strerror(errno), rc);
    }

    return &THREAD_EXITED;
}

void* run_thread_generation(void* arg){
    char** argv = (char**)arg;
    int rc = 0;
    struct threadlist* start_of_threadlist = calloc(1,
        sizeof(struct threadlist));
    struct threadlist* end_of_threadlist = start_of_threadlist;
    printf("allocation start_of_threadlist\n" );
    start_of_threadlist->next = NULL;
    start_of_threadlist->prev = NULL;
    start_of_threadlist->thread_id = pthread_self();

    printf("port in thread generation is %s\n", argv[3]);
    
    pthread_mutex_t mutex_threadlist = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond_threadlist = PTHREAD_COND_INITIALIZER;
    struct ticket_lock_t ticket_threadlist = TICKET_LOCK_INITIALIZER;

    struct cleanup_handler_args cleanup_args;
    cleanup_args.thread_self = start_of_threadlist->thread_id;
    cleanup_args.threadlist_element = start_of_threadlist;
    cleanup_args.mutex_threadlist = &mutex_threadlist;
    pthread_cleanup_push(thread_generation_cleanup, &cleanup_args);

    ticket_lock(&ticket_threadlist);

    for(;;) {
        
        if(rc = pthread_mutex_lock(&mutex_threadlist)){
                fprintf(stderr, "mutex_threadlist lock failed in "
                "thread generation: %s\n", strerror(errno));
                pthread_exit(NULL);
        }
        struct threadlist* iter = start_of_threadlist;
        while(iter->next!=NULL){
            iter = iter->next;
        }
        end_of_threadlist = iter;
        
        ticket_unlock(&ticket_threadlist);
        
        if(conn_thread_count)
        {
            if(rc = pthread_cond_wait(&cond_threadlist, &mutex_threadlist)){
                fprintf(stderr, "pthread_cond_wait failed in "
                "thread generation: %s\n", strerror(errno));
                pthread_exit(NULL);
            }
            
            ticket_lock(&ticket_threadlist);
            end_of_threadlist->next = calloc(1, sizeof(struct threadlist));
            end_of_threadlist->next->prev = end_of_threadlist;
            end_of_threadlist->next->next = NULL;
            end_of_threadlist = end_of_threadlist->next;
        }
        else {
            pthread_testcancel();
            ticket_lock(&ticket_threadlist);
        }
        
        struct thread_arguments *thread_arg = calloc(1, sizeof(struct thread_arguments));
        thread_arg->argv = argv;
        thread_arg->cond_threadlist = &cond_threadlist;
        thread_arg->threadlist_element = end_of_threadlist;
        thread_arg->ticket = &ticket_threadlist;
        printf("allocation thread\n" );
        
        if(rc = pthread_create(&(end_of_threadlist->thread_id), NULL,
        run_connection, thread_arg)){
            fprintf(stderr, "pthread_create failed in "
            "thread generation: %s\n", strerror(errno));
            pthread_exit(NULL);
        }
        
        conn_thread_count++;
        
        if(rc = pthread_mutex_unlock(&mutex_threadlist)){
            fprintf(stderr, "mutex_threadlist unlock failed in "
            "thread generation: %s\n", strerror(errno));
            pthread_exit(NULL);
        }
        

/*
        if(rc = usleep(USECS)){
            fprintf(stderr, "usleep failed in "
            "thread generation: %s\n", strerror(errno));
            pthread_exit(NULL);
        }
*/
    }

    pthread_cleanup_pop(EXEC_CLNUP);

    /* will never reach this */
    return 0;
}

int main(int argc, char **argv) {
    int rc = 0;
    /* check usage */
	if (argc != 4) {
		fprintf(stderr, "Usage:\n ./telnet-proxy <remote ip> <remote port> "
				"<local port>\n");
		return 1;
	}
    printf("Press \'x\' and ENTER to close the program\n");
    pthread_t thread_generation;
    if(pthread_create(&thread_generation, NULL, run_thread_generation, argv)){
        fprintf(stderr, "pthread_create failed in "
        "main thread: %s\n", strerror(errno));
        return 1;
    }

    int c = 0;
    while(c != 'x'){
        c = getchar();
    }

    printf("closing program\n");
    if(rc = pthread_cancel(thread_generation)){
        fprintf(stderr, "pthread_cancel failed in "
        "main thread: %s\n", strerror(errno));
        return 1;
    }
    if(rc = pthread_join(thread_generation, NULL)){
        fprintf(stderr, "pthread_join failed in "
        "main thread: %s\n", strerror(errno));
        return 1;
    }

	return 0;
}
