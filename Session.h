/*
 * Use an STL unordered map to store references to our sessions.
 */

#ifndef __SESSION__
#define __SESSION__

class CSession
{
private:
    std::string m_filename;

    pcap_t *m_pcap;
    pcap_dumper_t *m_pcap_dumper;

public:
    CSession(std::string filename);
    ~CSession(void);

    int addPacket(struct pcap_pkthdr *h, const u_char *pkt);
};

#endif
