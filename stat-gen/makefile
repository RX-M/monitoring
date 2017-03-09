TARGET = stat-gen
CLISRC = stat-gen.cpp
CC = g++
CFLAGS = -Wall -std=c++11

all: stat-gen

stat-gen: $(CLISRC)
	$(CC) -o $@ $(CLISRC) $(CFLAGS) $(LIBS)

clean:
	$(RM) $(TARGET)

