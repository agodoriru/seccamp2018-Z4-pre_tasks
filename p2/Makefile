CC=gcc
OBJS=main.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall -Werror
LDLIBS=-lpcap
TARGET=main
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

clean:
	rm -f $(OBJS) $(TARGET)
