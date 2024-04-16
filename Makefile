ifndef $(CC)
	CC = gcc
endif

# Build everything.
all: ping traceroute

# Build ping.
ping:
	$(CC) ping.c util.c -o ping362

# Build traceroute.
traceroute:
	$(CC) traceroute.c util.c -o traceroute362

clean:
	rm -r ping362 traceroute362