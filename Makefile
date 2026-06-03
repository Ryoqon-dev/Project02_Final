CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lws2_32

SERVER = Server.exe
CLIENT = Client.exe
TARGETS = $(SERVER) $(CLIENT)
OBJS = Server.o Client.o

.PHONY: all server client clean rebuild run-server run-client

all: $(TARGETS)

server: $(SERVER)

client: $(CLIENT)

$(SERVER): Server.o
	$(CC) -o $@ $^ $(LDFLAGS)

$(CLIENT): Client.o
	$(CC) -o $@ $^ $(LDFLAGS)

Server.o: Server.c Common.h
	$(CC) $(CFLAGS) -c Server.c -o $@

Client.o: Client.c Common.h
	$(CC) $(CFLAGS) -c Client.c -o $@

clean:
	del /Q $(TARGETS) $(OBJS) 2>nul || exit 0

rebuild: clean all

run-server: $(SERVER)
	$(SERVER)

run-client: $(CLIENT)
	$(CLIENT)
