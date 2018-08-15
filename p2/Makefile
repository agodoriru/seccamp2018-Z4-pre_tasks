CC=clang
OBJS=main.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Weverything -Werror -Wno-cast-align
LDLIBS=-lpcap
TARGET=main
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

clean:
	rm -f $(OBJS) $(TARGET)
