/*
 * Use an STL unordered map to store references to our sessions.
 */

#ifndef __SESSIONHASH__
#define __SESSIONHASH__

#include <tr1/unordered_map>

#include "Session.h"

class CSessionHash
{
private:
    std::tr1::unordered_map<uint64_t, CSession *> m_hash;
    uint64_t calcHash(uint8_t *saddr, uint8_t *daddr, uint8_t addr_len, uint16_t sport, uint16_t dport);

public:
    CSessionHash(void);
    ~CSessionHash(void);

    CSession *getSession(uint8_t *saddr, uint8_t *daddr, uint8_t addr_len, uint16_t sport, uint16_t dport);
    bool flush(void);
};

#endif
