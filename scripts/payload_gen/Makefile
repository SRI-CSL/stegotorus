SHELL = /bin/sh

CC = gcc
OPTFLAGS = -g  

CFLAGS = -Wall -O3  -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $(OPTFLAGS) $(INCLUDES)
LDLIBS =  -lpcap -lz # -ldmalloc
#INCLUDES = -I./libpcap-0.7.1


PAYLOAD_GEN_SRC = payload_gen.c \
	msg.c \
	flow.c \

PAYLOAD_GEN_OBJ = $(PAYLOAD_GEN_SRC:.c=.o)

all:		payload_gen

payload_gen:	$(PAYLOAD_GEN_OBJ)  
		$(CC) -o $@ $(PAYLOAD_GEN_OBJ) $(LDLIBS)


clean:
	rm -f *.o core* payload_gen *~



