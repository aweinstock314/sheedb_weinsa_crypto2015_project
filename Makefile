.PHONY: all clean

define NAMES
$(1)Alice$(2) $(1)Bob$(2) $(1)Eve$(2)
endef

CARDOUTPUT=$(call NAMES,cards/,.card) $(call NAMES,includecards/,.card.h)

all: bin/ ${CARDOUTPUT}

bin/:
	mkdir bin

${CARDOUTPUT}: keygen.py
	./keygen.py

clean:
	rm -rf bin/ cards/ includecards/
