#include <stdio.h>
#include <string>
#include <pcap.h>

#include <assert.h>

#include "Session.h"

CSession::CSession(std::string filename)
{
    m_filename = filename;

    m_pcap = pcap_open_dead(DLT_EN10MB, 9000);
    if (m_pcap == NULL) {
        fprintf(stderr, "\n");
    } else {
        // Open the file.
        m_pcap_dumper = pcap_dump_open(m_pcap, m_filename.c_str());
        if (m_pcap_dumper == NULL) {
            fprintf(stderr, "Could not open '%s' for output: %s\n",
                    m_filename.c_str(), pcap_geterr(m_pcap));
            pcap_close(m_pcap);
            m_pcap = NULL;
       }
    }
}

CSession::~CSession(void)
{
    if (m_pcap_dumper != NULL) {
        pcap_dump_close(m_pcap_dumper);
        m_pcap_dumper = NULL;
    }
    if (m_pcap != NULL) {
        pcap_close(m_pcap);
        m_pcap = NULL;
    }
}

int
CSession::addPacket(struct pcap_pkthdr *h, const u_char *pkt)
{
    assert(m_pcap != NULL);
    assert(m_pcap_dumper != NULL);

    pcap_dump((unsigned char *)m_pcap_dumper, h, pkt);

    return 0;
}
