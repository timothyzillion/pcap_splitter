
all: splitter

splitter: splitter.o
	echo BLAH

%.o : %cc
	g++ -c $(CFLAGS) $< $@
