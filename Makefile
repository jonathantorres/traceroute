CFLAGS = gcc -g -std=gnu11 -Wall -Wextra

traceroute: traceroute.c traceroute.h ipv6.h icmpv6.h
	$(CFLAGS) $< -o ./bin/$@

.PHONY: clean
clean:
	rm -f ./*.o ./*.h.gch
	rm -fr ./bin
	mkdir ./bin && touch ./bin/.gitkeep
