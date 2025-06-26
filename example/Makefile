all:
	$(CC) -c src.c $(CFLAGS) -fsanitize=address -o src.o
	$(CC) src.o -o prog $(CFLAGS) -fsanitize=address $(LDFLAGS)
	$(CC) -c src-meta.c $(CFLAGS) -fsanitize=address -o src-meta.o
	$(CC) src-meta.o -o prog.meta $(CFLAGS) -fsanitize=address $(LDFLAGS)

clean:
	rm -f src.o prog
	rm -f src-meta.o prog.meta