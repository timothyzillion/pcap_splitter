/*
 * Use an STL unordered map to store references to our sessions.
 */

#ifndef __SESSION__
#define __SESSION__

class CSession
{
public:
    std::string m_filename;
    FILE *m_file;

    CSession(std::string filename);

    int add_packet(struct pcap_pkthdr *h, const u_char *pkt);
};

#endif
