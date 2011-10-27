
all: splitter

clean:
	rm -f splitter.o pcap_splitter

splitter: splitter.o hash_64a.o
	gcc -g -o pcap_splitter splitter.o hash_64a.o -lpcap

%.o : %cc
	g++ -g -c $(CFLAGS) $< $@
