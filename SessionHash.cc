#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>

#include <pcap.h>

#include "Session.h"
#include "SessionHash.h"

#include "fnv.h"

CSessionHash::CSessionHash(void)
{
}

CSessionHash::~CSessionHash(void)
{
    m_hash.clear();
}

CSession *
CSessionHash::getSession(uint8_t *saddr, uint8_t *daddr, uint8_t addr_len, uint16_t sport, uint16_t dport)
{
    uint64_t hashcode;
    std::tr1::unordered_map<uint64_t, CSession *>::iterator iter;

    hashcode = calcHash(saddr, daddr, addr_len, sport, dport);
    if ((iter = m_hash.find(hashcode)) != m_hash.end()) {
        return iter->second;
    }

    // generate a filename from our input
    std::string filename;
    char addr_buffer[INET6_ADDRSTRLEN];
    char port_buffer[6];

    if (inet_ntop(addr_len == 4 ? AF_INET : AF_INET6,
                  (const char *)saddr, addr_buffer, INET6_ADDRSTRLEN) == NULL) {
        return NULL;
    }

    sprintf(port_buffer, "%u", sport);
    filename += addr_buffer;
    filename += "_";
    filename += port_buffer;

    if (inet_ntop(addr_len == 4 ? AF_INET : AF_INET6,
                  (const char *)daddr, addr_buffer, INET6_ADDRSTRLEN) == 0) {
        return NULL;
    }

    sprintf(port_buffer, "%u", sport);
    filename += "__";
    filename += addr_buffer;
    filename += "_";
    filename += port_buffer;
    filename += ".pcap";

    m_hash[hashcode] = new CSession(filename);

    // Need to create a new hash entry
    return m_hash[hashcode];
}

uint64_t
CSessionHash::calcHash(uint8_t *saddr, uint8_t *daddr, uint8_t addr_len, uint16_t sport, uint16_t dport)
{
    // we're going to hash over two addresses, and two ports.
    int len = (2 * addr_len) + 2 * 2;
    uint8_t *buf = (uint8_t *)malloc(len);

    uint64_t hash;

    if (buf == NULL) {
        fprintf(stderr, "Allocation failed\n");
        return 0;
    }

    hash = fnv_64a_buf(buf, len, FNV1A_64_INIT);
    return hash;
}

bool
CSessionHash::flush(void)
{
}
