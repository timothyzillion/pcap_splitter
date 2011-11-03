#include <string>
#include <pcap.h>

#include "Session.h"


CSession::CSession(std::string filename)
{
    m_filename = filename;
}

int
CSession::addPacket(struct pcap_pkthdr *h, const u_char *pkt)
{
    return 0;
}
