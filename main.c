#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <pcap.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <getopt.h>
#include <iconv.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>

#include "md5.h"
#include "exp802.h"

int debug_mode;

pcap_t *handle=NULL;    /* device handler */
int username_len;
int password_len;
char username[USER_NAME_LEN];
char password[PASS_WORD_LEN];

u_char protocol_type[2] = {0x88,0x8e};  /* PROTOCOL EAPOL */

u_char eap_start[EAP_START_LEN];           /* start frame */
u_char eap_logoff[EAP_START_LEN];           /* start frame */
EAP_FRAME *Eap_response_ident;  /* response_ident frame */
EAP_FRAME *Eap_response_md5;  /* response_md5 frame */

u_char BroadCast[MAC_ADDRESS_LEN]={0xff,0xff,0xff,0xff,0xff,0xff};/* Broadcast the frame */
u_char Local_mac[MAC_ADDRESS_LEN];    /* Local MAC Address */
u_char Dest_mac[MAC_ADDRESS_LEN];     /* Dest MAC Address */
u_char Nearest_mac[MAC_ADDRESS_LEN]={0x01,0x80,0xc2,0x00,0x00,0x03};

pcap_if_t *alldevs;
pcap_if_t *dev;
char dev_name[100]; /* Save device name */

static int init_frames()
{
    u_char start_data[4] = {0x01,0x01,0x00,0x00};   /* version:0x01,type:0x01-EAP-START,extra data length:0x00,0x00 */
    u_char logoff_data[4] = {0x01,0x02,0x00,0x00};   /* version:0x01,type:0x02-EAP-LOGOFF,extra data length:0x00,0x00 */

    /* EAP-START */
    memset(eap_start,0x00,EAP_START_LEN);
    memcpy(eap_start,BroadCast,MAC_ADDRESS_LEN);
    memcpy(eap_start+MAC_ADDRESS_LEN,Local_mac,MAC_ADDRESS_LEN);
    memcpy(eap_start+MAC_ADDRESS_LEN*2,protocol_type,2);
    memcpy(eap_start+MAC_ADDRESS_LEN*2+2,start_data,4);

    /* EAP-LOGOFF */
    memset(eap_logoff,0x00,EAP_START_LEN);
    memcpy(eap_logoff,Nearest_mac,MAC_ADDRESS_LEN);
    memcpy(eap_logoff+MAC_ADDRESS_LEN,Local_mac,MAC_ADDRESS_LEN);
    memcpy(eap_logoff+MAC_ADDRESS_LEN*2,protocol_type,2);
    memcpy(eap_logoff+MAC_ADDRESS_LEN*2+2,logoff_data,4);

    /* EAP-RESPONSE-IDENTITY */
    Eap_response_ident = (EAP_FRAME*)malloc(sizeof(EAP_FRAME));
    if(Eap_response_ident==NULL)
    {
        printf("Eap_response_ident malloc failed\n");
        return ERROR;
    }
    memset(Eap_response_ident,0x00,EAP_MESSAGE_LEN);
    memcpy(Eap_response_ident->SrcMac,Local_mac,MAC_ADDRESS_LEN);
    memcpy(Eap_response_ident->ProtocolType,protocol_type,2);
    Eap_response_ident->Version = 0x01;
    Eap_response_ident->Type = EAP_PACKET;
    Eap_response_ident->ExtenData.Type = EAP_IDENTITY;
    Eap_response_ident->ExtenData.Code = EAP_RESPONSE;

    /* EAP-RESPONSE-IDENTITY */
    Eap_response_md5 = (EAP_FRAME*)malloc(sizeof(EAP_FRAME));
    if(Eap_response_md5==NULL)
    {
        printf("Eap_response_md5 malloc failed\n");
        return ERROR;
    }
    memset(Eap_response_md5,0x00,EAP_MESSAGE_LEN);
    memcpy(Eap_response_md5->SrcMac,Local_mac,MAC_ADDRESS_LEN);
    memcpy(Eap_response_md5->ProtocolType,protocol_type,2);
    Eap_response_md5->Version = 0x01;
    Eap_response_md5->Type = EAP_PACKET;
    Eap_response_md5->ExtenData.Type = EAP_MD5_CHALLENGE;
    Eap_response_md5->ExtenData.Code = EAP_RESPONSE;
    return DONE;
}

static int init_device()
{
    /* subnet mask */
    bpf_u_int32 maskcodep;
    char *maskcode;

    /* ip address */
    bpf_u_int32 netip;
    char *ip;

    /*error buffer*/
    char errbuff[PCAP_ERRBUF_SIZE];

    int i,cho;/* cho for user to choose a Network InterfaceCard */

    pcap_if_t *d;/* temp variable */

    /* list all the device on the computer */
    if(pcap_findalldevs(&alldevs,errbuff)==-1)
    {
        printf("%s\n",errbuff);
        return ERROR;
    }
    for(d=alldevs,i=1;d;d=d->next,i++)
    {
        printf("%d. %s:\n",i,d->name);
        if(pcap_lookupnet(d->name,&netip,&maskcodep,errbuff)==-1)
        {
            printf("%s\n",errbuff);
            continue;
        }
        ip = inet_ntoa2(netip);
        maskcode = inet_ntoa2(maskcodep);
        printf("\tip : %s\n\tmaskcode: %s\n",ip,maskcode);
    }
    /* make a choice */
    printf("which one?\n");
    scanf("%d",&cho);
    for(i=0,dev=alldevs;i<cho-1;i++,dev=dev->next);

    printf("device %s selected\n",dev->name);
    memcpy(dev_name,dev->name,strlen(dev->name)+1);

    /* get device basic infomation */
    struct ifreq ifr;
    int sock;
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("socket");
        return ERROR;
    }
    strcpy(ifr.ifr_name, dev->name);

    // get Mac address
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("ioctl");
        return ERROR;
    }
    memcpy(Local_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    printf("ether dst %02x:%02x:%02x:%02x:%02x:%02x and ether proto 0x888e\n",Local_mac[0], Local_mac[1],Local_mac[2], Local_mac[3],Local_mac[4], Local_mac[5]);


    /* open device */
    if((handle=pcap_open_live(dev->name,1518,1,1000,errbuff))==NULL)
    {
        printf("open device %s failed\n",dev->name);
        return ERROR;
    }

    pcap_freealldevs(alldevs);

    return DONE;
}

static int send_usrname(EAP_FRAME *requestframe)
{
    memcpy(Eap_response_ident->DestMac,Nearest_mac,MAC_ADDRESS_LEN);

    Eap_response_ident->Length = username_len+EAP_EXTENDATA_BASE_LEN;
    swapbyte((u_char*)&Eap_response_ident->Length);

    Eap_response_ident->ExtenData.Length = username_len+EAP_EXTENDATA_BASE_LEN;
    swapbyte((u_char*)&Eap_response_ident->ExtenData.Length);

    Eap_response_ident->ExtenData.Id = requestframe->ExtenData.Id;

    memcpy(Eap_response_ident->ExtenData.Data,username,username_len);

    /* printf("size %d\n",sizeof(*Eap_response_ident)); */
    if (pcap_sendpacket(handle, (u_char*)Eap_response_ident, EAP_MESSAGE_LEN) != 0)
    {
        printf("Error Sending the packet: %s\n", pcap_geterr(handle));
        return ERROR;
    }
    if(debug_mode)
    {
        printf("EAP-Response-Identity sending...\n");
    }
    //exit(0);
    return DONE;
}

static u_char *get_md5(u_char *str,int len)
{
    static md5_byte_t digest[16];
	md5_state_t state;
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)str, len);
	md5_finish(&state, digest);

    return (u_char*)digest;
}

static int send_passwd(EAP_FRAME *requestframe)
{
    u_char str[MAX_MD5_STR];
    int len;

    EAP_MD5_VALUE *final_key = (EAP_MD5_VALUE*)(Eap_response_md5->ExtenData.Data);
    EAP_MD5_VALUE *attach_key = (EAP_MD5_VALUE*)requestframe->ExtenData.Data;
    printf("length of challenge value: %d\n",attach_key->Size);

    final_key->Size = attach_key->Size;

    memcpy(str,&requestframe->ExtenData.Id,sizeof(u_char));
    len = sizeof(u_char);

    memcpy(str+len,password,password_len);
    len += password_len;

    memcpy(str+len,attach_key->value,attach_key->Size);
    len += attach_key->Size;

    memcpy(final_key->value,get_md5(str,len),final_key->Size);


    memcpy(Eap_response_md5->DestMac,Nearest_mac,MAC_ADDRESS_LEN);

    Eap_response_md5->Length = username_len+EAP_EXTENDATA_BASE_LEN+sizeof(EAP_MD5_VALUE);
    swapbyte((u_char*)&Eap_response_md5->Length);

    Eap_response_md5->ExtenData.Length = username_len+EAP_EXTENDATA_BASE_LEN+sizeof(EAP_MD5_VALUE);
    swapbyte((u_char*)&Eap_response_md5->ExtenData.Length);

    Eap_response_md5->ExtenData.Id = requestframe->ExtenData.Id;

    memcpy(Eap_response_md5->ExtenData.Data+sizeof(EAP_MD5_VALUE),username,username_len);

    printf("size %d\n",sizeof(*Eap_response_md5));
    if (pcap_sendpacket(handle, (u_char*)Eap_response_md5, EAP_MESSAGE_LEN) != 0)
    {
        printf("Error Sending the packet: %s\n", pcap_geterr(handle));
        return ERROR;
    }
    printf("EAP-Response_MD5_Challenge sending...\n");
    //exit(0);
    return DONE;
}

static int send_eap_start()
{
    if (pcap_sendpacket(handle, eap_start, EAP_START_LEN) != 0)
    {
        printf("Error Sending the packet: %s\n", pcap_geterr(handle));
        return ERROR;
    }
    printf("EAP-START sending...\n");
    return DONE;
}

static int send_eap_logoff()
{
    if (pcap_sendpacket(handle, eap_logoff, EAP_START_LEN) != 0)
    {
        printf("Error Sending the packet: %s\n", pcap_geterr(handle));
        return ERROR;
    }
    printf("EAP-LOGOFF sending...\n");
    return DONE;
}

static int logon()
{
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    /* username & password */
    ///*
    //memcpy(username,"E10914004",9);
    //memcpy(password,"1401",4);
    //*/
    ///*
    printf("your User Name?\n");
    scanf("%s",username);
    printf("your pass word?\n");
    scanf("%s",password);
    //*/
    username_len = strlen(username);
    password_len = strlen(password);

    /* send EAP-START */
    if(send_eap_start()!=DONE)
    {
        perror("EAP-start send failed\n");
        return ERROR;
    }

    /* pcap_next_ex */
    while((res=pcap_next_ex(handle,&header,&pkt_data))>=0)
    {
        /* recieved frame */
        EAP_FRAME *prdframe = (EAP_FRAME*)pkt_data;
        memcpy(Dest_mac,prdframe->SrcMac,MAC_ADDRESS_LEN);

        if(prdframe->ProtocolType[0]!=protocol_type[0]||prdframe->ProtocolType[1]!=protocol_type[1])
        {
            //printf("not 0x888e\n");
            continue;
        }

        /* time out */
        if(res==0)
        {
            //printf("time out retrying...\n");
            //
    /* send EAP-START */
    //if(send_eap_start()!=DONE)
    //{
      //  perror("EAP-start send failed\n");
        //return ERROR;
    //}
    //
            continue;
        }

	//if(strcmp((char*)prdframe->DestMac,(char*)Local_mac)!=0)
        //{
            /* printf("How could I recieve a frame that not belong me!!~Am I crazy?!!\n"); */
          //  continue;
        //}

        if(prdframe->ExtenData.Code==EAP_REQUEST)
        {
            switch(prdframe->ExtenData.Type)
            {
                case EAP_IDENTITY:
                    send_usrname(prdframe);
                    break;
                case EAP_MD5_CHALLENGE:
                    send_passwd(prdframe);
                    break;
            }
        }
        else if(prdframe->ExtenData.Code==EAP_SUCCESS)
        {
            printf("logon success!\n");
            char cmd[100] = "sudo dhclient ";
            system("sudo dhclient -r");
            printf("device name:%s\n",dev_name);
            system(strcat(cmd,dev_name));
        }
        else if(prdframe->ExtenData.Code==EAP_FAILURE)
        {
            return ERROR;
        }
    }
    if(res!=0)
    {
        printf("res!=0 & res = %d\n",res);
        return ERROR;
    }
    return DONE;
}

static int logoff()
{
    send_eap_logoff();

    pcap_close(handle);
    return DONE;
}

static void onExit(int sig)
{
    printf("Bye Bye Honey~(*^_^*)\n");
    logoff();
    exit(0);
}

int main(int args,char **argv)
{
    char cho;
    debug_mode = 0;

	if(args&&strcmp(*argv,"-d")==0)
		debug_mode = 1;
    if(init_device()!=DONE)
    {
        perror("device initialized failed\n");
        return ERROR;
    }

    if(init_frames()!=DONE)
    {
        perror("frame initialized failed\n");
        return ERROR;
    }

    signal (SIGINT, onExit);
    signal (SIGTERM, onExit);

    while(logon()!=DONE)
    {
        printf("logon failed retry?(Y?)\n");
        //getchar();
        //scanf("%c",&cho);
        cho='Y';
        if(cho!='Y'&&cho!='y')
        {
            printf("Oh my God , Game Over!~\nehhhhh~~~~T^T~\n");
            logoff();
            return DONE;
        }
    }
    printf("Bye Bye Honey~(*^_^*)\n");
    return DONE;
}