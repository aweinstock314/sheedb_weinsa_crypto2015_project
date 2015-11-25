.PHONY: all clean

define NAMES
$(1)Alice$(2) $(1)Bob$(2) $(1)Eve$(2)
endef

CARDOUTPUT=$(call NAMES,cards/,.card) $(call NAMES,includecards/,.card.h)
CCFLAGS=-O2 -std=c++11 -Wall -Wextra -pedantic

all: bin/ bin/atm ${CARDOUTPUT}

bin/:
	mkdir bin

bin/atm: bin/ src/atm.cpp src/constants.h
	g++ ${CCFLAGS} src/atm.cpp -o bin/atm

${CARDOUTPUT}: keygen.py
	./keygen.py

clean:
	rm -rf bin/ cards/ includecards/
