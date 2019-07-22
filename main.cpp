#include <pcap.h>
#include <cstdio>
#include <vector>
#include <cstring>
#include "packetparser.h"

int main(int argc, char* argv[]) {
  if (argc != 2) {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  std::vector<PACKET*> v_packet;
  while (true) {
    struct pcap_pkthdr* header = nullptr;
    const u_char* packet = nullptr;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    PACKET* p = new PACKET(header, packet);
    v_packet.push_back(p);

    printf("(No.%d) %u bytes captured\n", v_packet.size(), header->caplen);
    p->print();
    printf("\n\n\n");
  }

  pcap_close(handle);
  for (int i = 0; i < v_packet.size(); i++)
      safeFree(v_packet[i]);
  v_packet.clear();
  return 0;
}

