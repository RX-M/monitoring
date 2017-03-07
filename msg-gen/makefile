TARGET = msg-gen
CLISRC = msg-gen.cpp
CC = g++
CFLAGS = -Wall -std=c++11

all: msg-gen

msg-gen: $(CLISRC)
	$(CC) -o $@ $(CLISRC) $(CFLAGS) $(LIBS)

clean:
	$(RM) $(TARGET)

