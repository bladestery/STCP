/*
 * transport.c
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <time.h>
#include <arpa/inet.h>

#define MAX_SEND_WINDOW_SIZE 3027
#define MAX_RECV_WINDOW_SIZE 3027
#define MIN_CWND_SIZE 3027
#define MAX_PAYLOAD_SIZE 536
#define MAX_SIZE 556

enum {
    CSTATE_ESTABLISHED,
    CSTATE_CLOSED,
    CSTATE_LISTEN,
    CSTATE_SYN_SENT,
    CSTATE_SYN_RCVD,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_1a,
    CSTATE_FIN_WAIT_1b,
    CSTATE_FIN_WAIT_2,
    CSTATE_CLOSE_WAIT,
    CSTATE_LAST_ACK,
    CSTATE_CLOSING
};    /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */
    
    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    
    /* any other connection-wide global variables go here */
    
    /* Variables on our end */
    tcp_seq max_ACK_rcvd;
    uint16_t our_wndw;
    tcp_seq nxt_seqnum;
    
    /* Variables on the other end */
    tcp_seq nxt_exp; /* used to keep track of what the other side is expecting and what we are expecting from them */
    uint16_t other_wndw;
    
    
} context_t;


static void generate_initial_seq_num(context_t *ctx);
tcphdr *create_tcphdr(uint8_t th_flag, context_t *ctx);
void send_packet(mysocket_t sd, context_t *ctx, uint8_t th_flag);
void est_handshake(mysocket_t sd, context_t *ctx);

static void control_loop(mysocket_t sd, context_t *ctx);
void end_handshake(mysocket_t sd, context_t *ctx);
void update_wndw(context_t *ctx, tcphdr *tcp_hdr);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);
    
    generate_initial_seq_num(ctx);
    
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    
    if (is_active) {
        ctx->nxt_seqnum = ctx->initial_sequence_num;
        
        send_packet(sd, ctx, TH_SYN);
        ctx->connection_state = CSTATE_SYN_SENT;
    }
    else {
        ctx->nxt_seqnum = ctx->initial_sequence_num;
        ctx->connection_state = CSTATE_LISTEN;
    }
    ctx->our_wndw = MAX_SEND_WINDOW_SIZE;
    ctx->other_wndw = MAX_RECV_WINDOW_SIZE; /* Will be updated when first packet arrives */
    printf("establishing handshake\n");
    est_handshake(sd, ctx);
    
    if (ctx->connection_state != CSTATE_ESTABLISHED)
        fprintf(stderr, "CSTATE not established!\n");
    
    stcp_unblock_application(sd);

    control_loop(sd, ctx);
    printf("done\n");
    /* do any cleanup here */
    free(ctx);
}

tcphdr *create_tcphdr(uint8_t th_flag, context_t *ctx)
{
    tcphdr *ret = (tcphdr *) calloc(sizeof(tcphdr), 1);
    assert(ret);
    
    ret->th_seq = htonl(ctx->nxt_seqnum);
    ret->th_flags = th_flag;
    ret->th_ack = (th_flag & TH_ACK) ? htonl(ctx->nxt_exp) : 0;
    ret->th_win = htons(MAX_SEND_WINDOW_SIZE);
    ret->th_off = 5;
    
    return ret;
}

/* specifically for sending TH_ACK/TH_SYN/TH_FIN */
void send_packet(mysocket_t sd, context_t *ctx, uint8_t th_flag)
{
    tcphdr *tcp_hdr = create_tcphdr(th_flag, ctx);
    printf("sending: th_seq: %d\nth_ack: %d\nth_flags: %u\n", ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack), tcp_hdr->th_flags);
    if (stcp_network_send(sd, tcp_hdr, sizeof(tcphdr), NULL) < (int) sizeof(tcphdr)) {
        fprintf(stderr, "send_packet failed to send entirety of packet\n");
    }
    ctx->other_wndw -= sizeof(tcphdr);
    ctx->nxt_seqnum++; /* expecting a ack with this seqnum */
    
    if (th_flag & TH_ACK)
        ctx->nxt_exp++; /* expecting seqnum of next received packet to be this (set during handshake) */

    free(tcp_hdr);
}

void est_handshake(mysocket_t sd, context_t *ctx)
{
    stcp_event_type_t flag;
    ssize_t rcvd;
    tcphdr *tcp_hdr;

    while (ctx->connection_state == CSTATE_SYN_SENT || ctx->connection_state == CSTATE_SYN_RCVD || ctx->connection_state == CSTATE_LISTEN) {
        
        /* APP has been blocked */
        flag = (stcp_event_type_t) stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        
        if (flag == NETWORK_DATA) {
            char buf[MAX_SIZE];
            rcvd = stcp_network_recv(sd, buf, MAX_SIZE);
            tcp_hdr = (tcphdr *) buf;
            
            switch (ctx->connection_state) {
                case CSTATE_LISTEN:
                    if (tcp_hdr->th_flags & TH_SYN) {
                        ctx->nxt_exp = ntohl(tcp_hdr->th_seq) + rcvd - tcp_hdr->th_off * 4 + 1;
                        update_wndw(ctx, tcp_hdr);
                        send_packet(sd, ctx, TH_ACK | TH_SYN);
                        ctx->connection_state = CSTATE_SYN_RCVD;
                    }
                    break;
                    
                case CSTATE_SYN_SENT:
                    if (tcp_hdr->th_flags & TH_SYN) {
                        ctx->nxt_exp = ntohl(tcp_hdr->th_seq) + rcvd - tcp_hdr->th_off * 4 + 1;
                        ctx->connection_state = CSTATE_SYN_RCVD;

                        if (tcp_hdr->th_flags & TH_ACK && ntohl(tcp_hdr->th_ack) == ctx->nxt_seqnum) {
                            ctx->max_ACK_rcvd = ntohl(tcp_hdr->th_ack);
                            ctx->nxt_seqnum++;
                            ctx->connection_state = CSTATE_ESTABLISHED;
                            send_packet(sd, ctx, TH_ACK);
                            update_wndw(ctx, tcp_hdr);
                            break;
                        }
                        send_packet(sd, ctx, TH_ACK | TH_SYN);
                        update_wndw(ctx, tcp_hdr);
                    }

                    break;
                    
                case CSTATE_SYN_RCVD:
                    if (tcp_hdr->th_flags & TH_ACK && ntohl(tcp_hdr->th_ack) == ctx->nxt_seqnum) {
                        ctx->nxt_exp = ntohl(tcp_hdr->th_seq) + rcvd - tcp_hdr->th_off * 4 + 1;
                        ctx->max_ACK_rcvd = ntohl(tcp_hdr->th_ack);
                        ctx->nxt_seqnum++;
                        update_wndw(ctx, tcp_hdr);
                        ctx->connection_state = CSTATE_ESTABLISHED;
                    }/* Here, the sliding window does not play any role yet. later an ACK will be accepted if it its > last recieved ack */
                    
                    break;
                    
                default:
                    printf("Invalid state\n");
                    break;
            }
        }
        else
            printf("Flag is not NETWORK_DATA!\n");
    }
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    srand(time(NULL));
    
#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 256;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        
        char buf[MAX_SIZE];
        size_t bytes_rcvd;
        uint16_t load_size;
        int len;
        tcphdr *tcp_hdr;
        uint8_t *temp;

        switch (event) {
            case NETWORK_DATA:
                bytes_rcvd = stcp_network_recv(sd, buf, MAX_SIZE);
                tcp_hdr = (tcphdr *) buf;
                load_size = bytes_rcvd - tcp_hdr->th_off * 4;
                
                update_wndw(ctx, tcp_hdr);
                
                // ERROR CHECKING
                printf("recieved\n");
                printf("th_flags on packet: %u\n", tcp_hdr->th_flags);
                
                printf("acknowledging (should be > max_ACK_rcvd: %d\n", ntohl(tcp_hdr->th_ack));
                printf("max_ACK_rcvd: %d\n", ctx->max_ACK_rcvd);
                printf("ctx->nxt_seqnum : %d\n", ctx->nxt_seqnum);
                
                printf("tcp_hdr->th_seq: %d\n", ntohl(tcp_hdr->th_seq));
                printf("load_size: %d\n", load_size);
                printf("ctx->nxt_exp : %d\n", ctx->nxt_exp);
                
                /* Reliable mode: Packet should be as expected, or in extraordinary circumstances: old data is retransmitted with new data */
                if ((ntohl(tcp_hdr->th_seq) == ctx->nxt_exp) || (ntohl(tcp_hdr->th_ack) > ctx->max_ACK_rcvd && ntohl(tcp_hdr->th_ack) <= ctx->nxt_seqnum) || (ntohl(tcp_hdr->th_seq) + load_size >= ctx->nxt_exp && ntohl(tcp_hdr->th_seq) + load_size <= ctx->nxt_exp + ctx->our_wndw)) {
                    
                    /* check if typical packet, check if valid ACK, check if packet falls within our window */

                    /* concatenate recieved old data */
                    if (ntohl(tcp_hdr->th_seq) + tcp_hdr->th_off * 4 < ctx->nxt_exp) {
                        load_size -= (ctx->nxt_exp - ntohl(tcp_hdr->th_seq) - tcp_hdr->th_off * 4);
                    }
                    
                    /* Pure TCP packet */
                    if (load_size == 0) {
                        ctx->nxt_exp++;

                        if (tcp_hdr->th_flags & TH_FIN) {
                            if (ctx->connection_state == CSTATE_FIN_WAIT_1 || ctx->connection_state == CSTATE_FIN_WAIT_1b) {
                                printf("ending sequence\n");
                                ctx->connection_state = CSTATE_FIN_WAIT_1a;
                                end_handshake(sd, ctx);
                                break;
                            }
                            else if (ctx->connection_state == CSTATE_FIN_WAIT_2) {
                                printf("ending sequence\n");
                                end_handshake(sd, ctx);
                            }
                            printf("server acks fin\n");
                            send_packet(sd, ctx, TH_ACK);
                            ctx->connection_state = CSTATE_CLOSE_WAIT;
                            stcp_fin_received(sd);
                        }
                    }
                    else if (load_size > 0) { /* Payload exists */
                        /* Pointer to the payload */
                        temp = (((uint8_t *) tcp_hdr) + tcp_hdr->th_off * 4);
                        
                        /* Take care of the extraordinary circumstance */
                        if ((ntohl(tcp_hdr->th_seq) + tcp_hdr->th_off * 4 < ctx->nxt_exp)) {
                            temp = (((uint8_t *) tcp_hdr)  + (ctx->nxt_exp - ntohl(tcp_hdr->th_seq)));
                        }
                        ctx->nxt_exp += load_size;
                        send_packet(sd, ctx, TH_ACK);
                        
                        stcp_app_send(sd, temp, load_size);
                        
                        /* TH_FIN is piggybacked */
                        if (tcp_hdr->th_flags & TH_FIN) {
                            if (ctx->connection_state == CSTATE_FIN_WAIT_1 || ctx->connection_state == CSTATE_FIN_WAIT_1b) {
                                printf("ending sequence\n");
                                ctx->connection_state = CSTATE_FIN_WAIT_1a;
                                end_handshake(sd, ctx);
                                break;
                            }
                            else if (ctx->connection_state == CSTATE_FIN_WAIT_2) {
                                printf("ending sequence\n");
                                end_handshake(sd, ctx);
                            }
                            /* Already ACKED! */
                            ctx->connection_state = CSTATE_CLOSE_WAIT;
                            stcp_fin_received(sd);
                        }
                    }
                    if (tcp_hdr->th_flags & TH_ACK && ntohl(tcp_hdr->th_ack) > ctx->max_ACK_rcvd && ntohl(tcp_hdr->th_ack) <= ctx->nxt_seqnum) {
                        ctx->max_ACK_rcvd = ntohl(tcp_hdr->th_ack);
                        ctx->nxt_seqnum++;
                                
                        /* All payload packets has been acked; recieving ack for TH_FIN */
                        if (ntohl(tcp_hdr->th_ack) == ctx->nxt_seqnum && (ctx->connection_state == CSTATE_FIN_WAIT_1)) {
                            printf("client recieving ACK for FIN\n");
                        
                            ctx->nxt_exp = ntohl(tcp_hdr->th_seq) + 1; /* not accounted for if load_size == 0 */
                            ctx->connection_state = CSTATE_FIN_WAIT_1b;
                            end_handshake(sd,ctx);
                            break;
                        }
                    }
                }
                
                /* re-send ack for oustanding packets */
                else if (ntohl(tcp_hdr->th_seq) != ctx->nxt_exp) {
                    ctx->nxt_exp--;
                    send_packet(sd, ctx, TH_ACK);
                }
                
                break;
                
            case APP_DATA:
                len = (ctx->other_wndw < MAX_SIZE - sizeof(tcphdr)) ? ctx->other_wndw : MAX_SIZE - sizeof(tcphdr);
                printf("app data\n");
                bytes_rcvd = stcp_app_recv(sd, buf, len);
                tcp_hdr = (tcphdr *) calloc(sizeof(tcphdr) + bytes_rcvd, 1);
                memcpy(tcp_hdr + 1, buf, bytes_rcvd);
                
                tcp_hdr->th_seq = htonl(ctx->nxt_seqnum);
                tcp_hdr->th_win = htons(MAX_SEND_WINDOW_SIZE);
                tcp_hdr->th_off = 5;
                printf("sending: th_seq: %d\nth_ack: %d\nth_flags: %u\n", ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack), tcp_hdr->th_flags);
                if (stcp_network_send(sd, tcp_hdr, sizeof(tcphdr) + bytes_rcvd, NULL) < (int) (sizeof(tcphdr) + bytes_rcvd)) {
                    fprintf(stderr, "send_packet failed to send entirety of packet\n");
                }
                
                free(tcp_hdr);
                ctx->other_wndw -= sizeof(tcphdr) + bytes_rcvd;
                ctx->nxt_seqnum += bytes_rcvd;

                break;
                
            case APP_CLOSE_REQUESTED:
                printf("close requested\n");
                end_handshake(sd, ctx);
                break;
                
            default:
                break;
        }
        
        
    }
}

void end_handshake(mysocket_t sd, context_t *ctx)
{
    tcphdr *tcp_hdr;
    char buf[MAX_SIZE];

    do  {
        switch (ctx->connection_state) {
            case CSTATE_ESTABLISHED:
                printf("client sends FIN\n");
                send_packet(sd, ctx, TH_FIN);
                ctx->connection_state = CSTATE_FIN_WAIT_1;
                
                return;
                
            case CSTATE_FIN_WAIT_1a:
                printf("recieved FIN after sent FIN\n");
                stcp_fin_received(sd);
                send_packet(sd, ctx, TH_ACK);
                ctx->connection_state = CSTATE_CLOSING;
                    
                break;
                    
            case CSTATE_FIN_WAIT_1b:
                printf("recieved ACK after sent FIN\n");
                ctx->connection_state = CSTATE_FIN_WAIT_2;
                    
                return;
                
            case CSTATE_FIN_WAIT_2:
                printf("Recieved final FIN\n");
                stcp_fin_received(sd);
                send_packet(sd, ctx, TH_ACK);
                ctx->connection_state = CSTATE_CLOSED;
                
                break;
                
            case CSTATE_CLOSING:
                printf("Recieved final ACK\n");
                if (tcp_hdr->th_flags & TH_ACK && ntohl(tcp_hdr->th_ack) == ctx->nxt_seqnum) {
                    update_wndw(ctx, tcp_hdr);
                    ctx->nxt_exp++;
                    ctx->max_ACK_rcvd = ntohl(tcp_hdr->th_ack);
                    ctx->nxt_seqnum++;
                    ctx->connection_state = CSTATE_CLOSED;
                }
                break;
                
            case CSTATE_CLOSE_WAIT:
                printf("Final FIN sent\n");
                send_packet(sd, ctx, TH_FIN);
                ctx->connection_state = CSTATE_LAST_ACK;
                break;
                
            case CSTATE_LAST_ACK:
                printf("Final ack recieved (last ack)\nth_ack: %d\n", ntohl(tcp_hdr->th_ack));
                printf("ctx seqnum : %d\n", ctx->nxt_seqnum);
                printf("th_flags: %u\n", tcp_hdr->th_flags);
                if (tcp_hdr->th_flags & TH_ACK && ntohl(tcp_hdr->th_ack) == ctx->nxt_seqnum) {
                    update_wndw(ctx, tcp_hdr);
                    ctx->nxt_exp++;
                    ctx->max_ACK_rcvd = ntohl(tcp_hdr->th_ack);
                    ctx->nxt_seqnum++;
                    ctx->connection_state = CSTATE_CLOSED;
                    send_packet(sd, ctx, TH_ACK);
                }
                break;
                
            default:
                break;
        }
        
        if (ctx->connection_state != CSTATE_CLOSED) {
            stcp_wait_for_event(sd, NETWORK_DATA, NULL);
            stcp_network_recv(sd, buf, MAX_SIZE);
            tcp_hdr = (tcphdr *) buf;
        }
        
    } while (ctx->connection_state != CSTATE_CLOSED);
    
    ctx->done = TRUE;
    
}

void update_wndw(context_t *ctx, tcphdr *tcp_hdr)
{
    ctx->other_wndw = (ntohs(tcp_hdr->th_win) > MAX_SEND_WINDOW_SIZE) ? MAX_SEND_WINDOW_SIZE : (ntohs(tcp_hdr->th_win));
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];
    
    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



