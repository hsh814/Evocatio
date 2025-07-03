CFLAGS = -fsanitize=address -g -O0

all:
	$(CC) -c src.c $(CFLAGS) -o src.o
	$(CC) src.o -o prog $(CFLAGS) $(LDFLAGS)
	$(CC) -c src-meta.c $(CFLAGS) -o src-meta.o
	$(CC) src-meta.o -o prog.meta $(CFLAGS) $(LDFLAGS)

clean:
	rm -f src.o prog
	rm -f src-meta.o prog.meta