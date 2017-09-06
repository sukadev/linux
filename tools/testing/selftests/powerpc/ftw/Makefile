
SRC = ../../../../../

INC = -I $(SRC)/include \
      -I $(SRC)/arch/powerpc/include \
      -I $(SRC)/arch/powerpc/include/uapi \
      -I $(SRC)/arch/powerpc/platforms/powernv

HEADERS = ftw-helpers.h

TESTS = ftw-1 ftw-2

ftw-helpers.o: ftw-helpers.c $(HEADERS)
	gcc -c $(INC) ftw-helpers.c

ftw-1.o: ftw-1.c $(HEADERS)
	gcc -c $(INC) ftw-1.c

ftw-1: ftw-1.o ftw-helpers.o ftw-helpers.h
	gcc -o ftw-1 ftw-1.o ftw-helpers.o -lpthread
	cp -f ftw-1 /tmp

ftw-2.o: ftw-2.c $(HEADERS)
	gcc -c $(INC) ftw-2.c

ftw-2: ftw-2.o ftw-helpers.o ftw-helpers.h
	gcc -o ftw-2 ftw-2.o ftw-helpers.o -lpthread
	cp -f ftw-2 /tmp

clean:
	rm -f $(TESTS) *.o
