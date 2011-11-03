#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <string>

#include "Session.h"
#include "SessionHash.h"

CSessionHash::CSessionHash()
{
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

    m_hash[hashcode] = new CSession(filename);

    // Need to create a new hash entry
    return m_hash[hashcode];
}

uint64_t
CSessionHash::calcHash(uint8_t *saddr, uint8_t *daddr, uint8_t addr_len, uint16_t sport, uint16_t dport)
{
    return 0;
}

bool
CSessionHash::flush(void)
{
}
