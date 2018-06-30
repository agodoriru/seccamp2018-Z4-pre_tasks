CC=gcc
OBJS=main.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall -I include
LDLIBS=-lpcap
TARGET=main
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)