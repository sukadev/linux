
SRC =	../../../../../

INC =

TESTS =  user-nx-test1 user-nx-test2 user-nx-test3 user-nx-test4

COMMON = compress.c nx-helpers.c
HEADERS = crb.h nx.h nx-842.h nx-helpers.h

compress.o: compress.c $(HEADERS)
	gcc -c $(INC) compress.c

nx-helpers.o: nx-helpers.c $(HEADERS)
	gcc -c $(INC) nx-helpers.c

user-nx-test1.o: user-nx-test1.c $(HEADERS)
	gcc -c $(INC) user-nx-test1.c

user-nx-test1: user-nx-test1.o $(COMMON) $(HEADERS)
	gcc $(INC) -o user-nx-test1 user-nx-test1.c $(COMMON)
	cp -f user-nx-test1 /tmp

clean:
	rm -f $(TESTS) *.o
