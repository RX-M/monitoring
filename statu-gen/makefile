TARGET = statu-gen
CLISRC = statu-gen.cpp
CC = g++
CFLAGS = -Wall -std=c++11

all: statu-gen

statu-gen: $(CLISRC)
	$(CC) -o $@ $(CLISRC) $(CFLAGS) $(LIBS)

clean:
	$(RM) $(TARGET)

