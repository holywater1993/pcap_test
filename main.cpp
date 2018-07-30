#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

struct ether_header
{
        unsigned char ether_dhost[6];
        unsigned char ether_shost[6];
        unsigned short ether_type;
};
 
struct ip_header
{
        unsigned char ip_header_len:4; 
        unsigned char ip_version:4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;
        unsigned char ip_frag_offset:5;
        unsigned char ip_more_fragment:1;
        unsigned char ip_dont_fragment:1;
        unsigned char ip_reserved_zero:1;
        unsigned char ip_frag_offset1;
        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        unsigned char ip_srcaddr[4];
        unsigned char ip_destaddr[4];
};
 
struct tcp_header
{
        unsigned short source_port;
        unsigned short dest_port;
        unsigned int sequence;
        unsigned int acknowledge;
        unsigned char reserved_part:4;
        unsigned char data_offset:4;
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        unsigned char ecn:1;
        unsigned char cwr:1;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent_pointer;
};

int print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
int print_tcp_header(const unsigned char *data);
void print_data(const unsigned char *data, int dataSize);

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  // printf("%d\n", PCAP_ERRBUF_SIZE);
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  // printf("test1\n");
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int offset=0;
    int totalOffsetSum=0;
    int res = pcap_next_ex(handle, &header, &pkt_data);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n============PACKET START===============\n");
    printf("%u bytes captured\n", header->caplen);
    offset = print_ether_header(pkt_data);
    totalOffsetSum = totalOffsetSum + offset;
    if(offset==0){
      continue; // ether type wrong
    }
    pkt_data = pkt_data + offset;       // raw_pkt_data의 14번지까지 이더넷
    offset = print_ip_header(pkt_data);
    totalOffsetSum = totalOffsetSum + offset;
    if(offset==0){
      continue; // this is not TCP
    }
    pkt_data = pkt_data + offset;           // ip_header의 길이만큼 오프셋
    offset = print_tcp_header(pkt_data);
    totalOffsetSum = totalOffsetSum + offset;
    int dataSize = header->caplen - totalOffsetSum;
    printf("\ndataSize = %d\n",dataSize);
    
    pkt_data = pkt_data + offset;           //print_tcp_header *4 데이터 위치로 오프셋
    print_data(pkt_data, dataSize);
  }

  pcap_close(handle);
  return 0;
}

int print_ether_header(const unsigned char *data)
{
        struct  ether_header *eh;               // 이더넷 헤더 구조체
        unsigned short ether_type;                     
        eh = (struct ether_header *)data;       // 받아온 로우 데이터를 이더넷 헤더구조체 형태로 사용
        ether_type=ntohs(eh->ether_type);       // 숫자는 네트워크 바이트 순서에서 호스트 바이트 순서로 바꿔야함
       
        if (ether_type!=0x0800)
        {
                printf("ether type wrong\n");
                return 0;
        }
        // 이더넷 헤더 출력
        printf("\nETHERNET HEADER\n");
        printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
                    eh->ether_shost[0],
                    eh->ether_shost[1],
                    eh->ether_shost[2],
                    eh->ether_shost[3],
                    eh->ether_shost[4],
                    eh->ether_shost[5]);
        printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
                    eh->ether_dhost[0],
                    eh->ether_dhost[1],
                    eh->ether_dhost[2],
                    eh->ether_dhost[3],
                    eh->ether_dhost[4],
                    eh->ether_dhost[5]);
    return 14;        
}
int print_ip_header(const unsigned char *data)
{
        struct  ip_header *ih;         
        ih = (struct ip_header *)data;  // 마찬가지로 ip_header의 구조체 형태로 변환
 
        printf("\nIP HEADER\n");
        printf("IPv%d ver \n", ih->ip_version);
        // Total packet length (Headers + data)
        printf("Packet Length : %d\n", ntohs(ih->ip_total_length)+14);
        // printf("TTL : %d\n", ih->ip_ttl);
        if(ih->ip_protocol == 0x06)
        {
                printf("Protocol : TCP\n");
                printf("Src IP Addr : %d.%d.%d.%d \n", int(ih->ip_srcaddr[0]), int(ih->ip_srcaddr[1]), int(ih->ip_srcaddr[2]), int(ih->ip_srcaddr[3]));
                printf("Dst IP Addr : %d.%d.%d.%d \n", int(ih->ip_destaddr[0]), int(ih->ip_destaddr[1]), int(ih->ip_destaddr[2]), int(ih->ip_destaddr[3]));
        }
        else{
                printf("This is not TCP\n");
                return 0;
        }
        // return to ip header size
        return ih->ip_header_len*4;
}
 
int print_tcp_header(const unsigned char *data)
{
        struct  tcp_header *th;
        th = (struct tcp_header *)data;
 
        printf("\nTCP HEADER\n");
        printf("Src Port Num : %d\n", ntohs(th->source_port) );
        printf("Dest Port Num : %d\n", ntohs(th->dest_port) );
        printf("\n");
 
        // return to tcp header size
        return th->data_offset*4;
}
 
void print_data(const unsigned char *data, int dataSize)
{
        printf("\nDATA\n");
        if(dataSize==0){
          printf("There is no DATA\n");
        }
        for(int i=0;i<dataSize;i++){
            printf("%02x ", data[i]);
            if(i==15){
              break;
            }
        }
        printf("\n");
}