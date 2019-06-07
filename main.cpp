#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnet.h>
#include <sys/types.h>

#include <iostream>
#include <string>
#include <fstream>
#define MILLION 1000000

using namespace std;

static int NF = 1;
static string myString[MILLION];


int binary_search (string target){ //algorism
    cout << "target is " << target << endl;
    int first=0;
    int last= 999999;
    int middle;

    while(1){
        if(first >= last) return 1;
        middle = first + ((last - first) / 2);
        cout << myString[middle] << endl;
        cout << "first is " << first << "middle is " << middle << "last is "<< last << endl;
        if(myString[middle].compare(target)==0)
            return 0;
        else if(myString[middle].compare(target) >0)
            last = middle - 1;
        else
            first = middle + 1 ;
    }
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}


/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    uint32_t mark, ifi, uid, gid;
    int ret;
    unsigned char *data, *secdata;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    if (nfq_get_uid(tb, &uid))
        printf("uid=%u ", uid);

    if (nfq_get_gid(tb, &gid))
        printf("gid=%u ", gid);

    ret = nfq_get_secctx(tb, &secdata);
    if (ret > 0)
        printf("secctx=\"%.*s\" ", ret, secdata);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d \n", ret);
        NF=1;
        string target;
        unsigned char buff[100]={0};
        int i;
        //dump(data, ret);
        struct libnet_ipv4_hdr* ipp = (struct libnet_ipv4_hdr*)data;
        if( (ipp->ip_p) == IPPROTO_TCP ){
            struct libnet_tcp_hdr* tcpp = (struct libnet_tcp_hdr*)(data + (ipp->ip_hl<<2) );
            int http_size = ntohs(ipp->ip_len) - (ipp->ip_hl<<2) - (tcpp->th_off<<2);
            if( http_size > 0 ){
                char* httpp = (char*)tcpp + (tcpp->th_off<<2);
                uint16_t count=(uint16_t)( ntohs(ipp->ip_len) - (ipp->ip_hl<<2) - (tcpp->th_off<<2) );
                if( !strncmp(httpp,"GET ",4) ){
                    for(int i=5;i<count;i++){
                        if( *(httpp+i) == 0x48 && *(httpp+i+1) == 0x6f && *(httpp+i+2) == 0x73 && *(httpp+i+3) == 0x74
                                && *(httpp+i+4) == 0x3a && *(httpp+i+5) == 0x20){
                            httpp= httpp+i+6;
                            break;// 'Host: ' finding..
                        }
                    }
                    for(i=0;i<count ; i++){
                        if( *(httpp+i)==0x0d && *(httpp+i+1)==0x0a ){
                            break;
                        }
                        else{
                            buff[i] = *(httpp+i);
                            target += buff[i];
                        }
                    }

                    NF = binary_search(target);
                    cout << "NF : " << NF << endl;
                }
            }
        }

    }

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)//packet start pointer, packet size
{// nfq_get_payload(tb,&data)  return packet_size   &data is start pointer
    uint32_t id = print_pkt(nfa);
    printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF, 0, NULL); //NF_ACCEPT = 1  NF_DROP = 0
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    uint32_t queue = 0;
    char buf[4096] __attribute__ ((aligned));
    int i=0;

    ifstream myFile("/root/1m_detect/top-1m-sort.csv");
    while( myFile.peek() != EOF ){
        getline(myFile,myString[i]);
        myString[i].capacity();
        cout << myString[i] << endl;
        i++;
    }


    if (argc == 2) {
        queue = atoi(argv[1]);
        if (queue > 65535) {
            fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, NULL);//&cb callback function
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    printf("setting flags to request UID and GID\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
        fprintf(stderr, "This kernel version does not allow to "
                        "retrieve process UID/GID.\n");
    }

    printf("setting flags to request security context\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
        fprintf(stderr, "This kernel version does not allow to "
                        "retrieve security context.\n");
    }

    printf("Waiting for packets...\n");

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
