#define MAC_ADDRESS_LEN 6
#define EAP_MESSAGE_LEN 60
#define EAP_START_LEN 64

#define USER_NAME_LEN 256
#define PASS_WORD_LEN 256
#define MAX_MD5_STR 512

#define DONE 0
#define ERROR 1

/* EAP_HEAD CODE */
#define EAP_REQUEST 0x01
#define EAP_RESPONSE 0x02
#define EAP_SUCCESS 0x03
#define EAP_FAILURE 0x04
#define EAP_OTHER 0x0a

/* EAP_DATA TYPE */
#define EAP_PACKET 0x00
#define EAP_IDENTITY 0x01
#define EAP_NOTIFICATION 0x02
#define EAP_MD5_CHALLENGE 0x04
#define EAP_ERROR 0x09
#define EAP_KEEPONLINE 0x14

typedef struct EAP_MD5_VALUE
{
    u_char Size;
    u_char value[16];   /* md5 challenge|response value & length 16 */
} EAP_MD5_VALUE;

typedef struct EAP_ExtenData
{
#define EAP_EXTENDATA_BASE_LEN 5
    u_char Code;
    u_char Id;
    u_short Length;
    u_char Type;
    u_char Data[37];
} EAP_ExtenData;

typedef struct EAP_FRAME
{
    u_char DestMac[MAC_ADDRESS_LEN];
    u_char SrcMac[MAC_ADDRESS_LEN];
    u_char ProtocolType[2];
    u_char Version;
    u_char Type;
    u_short Length;
    EAP_ExtenData ExtenData;   /* total length of EAP FRAME -> 60,so the etra is 42*/
} EAP_FRAME;


static int init_frames();
static int init_device();
static int send_eap_start();
static int send_eap_logoff();
static int logon();
static int logoff();
static int send_usrname(EAP_FRAME *requestframe);
static int send_passwd(EAP_FRAME *requestframe);
static u_char *get_md5(u_char *str,int len);
static void onExit(int sig);

static char *inet_ntoa2(bpf_u_int32 addr)
{
    char *ret=(char*)malloc(17*sizeof(char)),cht[16],t;
    int i,a;
    ret[0]=0;
    sprintf(cht,"%08x\0",addr);
    for(i=6;i>=0;i-=2)
    {
        t = cht[i+2];
        cht[i+2]=0;
        sscanf(cht+i,"%x",&a);
        sprintf(ret+strlen(ret),"%d.\0",a);
        cht[i+2]=t;
    }
    ret[strlen(ret)-1]=0;
    return ret;
}

static void swapbyte(u_char *data)
{
    //printf("swap before %02x %02x\n",data[0],data[1]);
    u_char t = data[1];
    data[1] = data[0];
    data[0] = t;
    //printf("swap after %02x %02x\n",data[0],data[1]);
}
