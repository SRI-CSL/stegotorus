
CFLAGS = -Wall  -g  -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 
LDLIBS =  -lpcap -lz 


PAYLOAD_GEN_SRC = payload_gen.c msg.c flow.c ../src/strncasestr.cc

PAYLOAD_GEN_OBJ = payload_gen.o msg.o flow.o 

all:		payload_gen

payload_gen:
	$(CC) -c $(CFLAGS) $(PAYLOAD_GEN_SRC)
	$(CC) -g -o $@ $(PAYLOAD_GEN_OBJ) $(LDLIBS)


clean:
	rm -fv *.o core* payload_gen *~ client.out server.out



