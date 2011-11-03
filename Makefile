OBJS=splitter.o SessionHash.o Session.o hash_64a.o

all: splitter

clean:
	rm -f pcap_splitter ${OBJS}

splitter: ${OBJS}
	g++ -g -o pcap_splitter ${OBJS} -lpcap

%.o : %cc
	g++ -g -c $(CFLAGS) $< $@
