all: wsu-crypt

wsu-crypt: main.o
	gcc -o wsu-crypt main.o

main.o: main.c
	gcc -c main.c

clean:
	rm -f main.o wsu-crypt
