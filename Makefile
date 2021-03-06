.PHONY: all clean

define NAMES
$(1)Alice$(2) $(1)Bob$(2) $(1)Eve$(2)
endef

# https://wiki.debian.org/Hardening#Notes_on_Memory_Corruption_Mitigation_Methods
MITIGATIONS=-fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIC -Wl,-zrelro,-znow

CARDOUTPUT=$(call NAMES,cards/,.card) $(call NAMES,includecards/,.card.h) includecards/metacard.h
CCFLAGS=-O2 ${MITIGATIONS} -std=c++11 -Wall -Wextra -pedantic -Werror

all: bin/ bin/atm bin/bank bin/proxy ${CARDOUTPUT}

bin/:
	mkdir bin

bin/atm: src/atm.cpp src/constants.h
	g++ ${CCFLAGS} src/atm.cpp src/utils.cpp -o $@ -lssl -lcrypto
	strip $@

bin/bank: src/bank.cpp src/constants.h includecards/metacard.h
	g++ ${CCFLAGS} -Iincludecards/ src/bank.cpp src/utils.cpp -o $@ -lssl -lcrypto -pthread
	strip $@

bin/proxy: src/proxy.cpp src/constants.h
	g++ ${CCFLAGS} src/proxy.cpp -o $@ -pthread
	strip $@

${CARDOUTPUT}: keygen.py
	./keygen.py

clean:
	rm -rf bin/ cards/ includecards/
