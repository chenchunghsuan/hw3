#include<time.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *filename = "NTP_sync.pcap";

    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }//end if
    
    printf("Open: %s\n", filename);
    int c=0;
    int total_amount = 0;
    int total_bytes = 0;
    while(1) {
        struct pcap_pkthdr *header = NULL;
        const u_char *content = NULL;
        int ret =
        pcap_next_ex(handle, &header, &content);
        if(ret == 1) { 
            total_amount++;
            total_bytes += header->caplen;
        }//end if success
        else if(ret == 0) {
            printf("Timeout\n");
        }//end if timeout
        else if(ret == -1) {
            fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
        }//end if fail
        else if(ret == -2) {
            printf("No more packet from file\n");
            break;
        }//end if read no more packet
c++; 
struct tm *ltime;
 char timestr[16];
    time_t local_tv_sec;    
local_tv_sec = header->ts.tv_sec;
ltime = localtime(&local_tv_sec);
strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
printf("%d.\n",c);    
printf("    Time: %s.%.6d\n", timestr, (int)header->ts.tv_usec);
    printf("    Length: %d bytes\n", header->len);
    printf("    Capture length: %d bytes\n", header->caplen);
    
}//end while
    //result
   // printf("Read: %d, byte: %d bytes\n", total_amount, total_bytes);

    //free
    pcap_close(handle);
    
    return 0;
}//end main


