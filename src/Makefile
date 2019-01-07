CC = g++
CFLAGS = -lcrypto -Wall -std=c++11

export CC
export CFLAGS

INCDIR = ../include
BINDIR = ../bin
OBJDIR = ../obj

$(OBJDIR)/%.o: %.cpp
	@[ -d $(OBJDIR) ] || mkdir $(OBJDIR)
	$(CC) -g -c -o $@ $< $(CFLAGS)

all: dsa

debug: $(BINDIR)/dsa.out
	gdb $(BINDIR)/dsa.out

dsa: $(patsubst %, $(OBJDIR)/%, dsa.o)
	@[ -d $(BINDIR) ] || mkdir $(BINDIR)
	$(CC) -g -o $(BINDIR)/dsa.out dsa.cpp $(CFLAGS)

.PHONY: clean run
clean:
	rm -rf $(BINDIR) $(OBJDIR)

run:
	$(BINDIR)/dsa.out
