#include <string>

#include <pcap.h>

#include "Session.h"





CSession::CSession(std::string filename)
{
}

int
CSession::add_packet(struct pcap_pkthdr *h, const u_char *pkt)
{
    return 0;
}
