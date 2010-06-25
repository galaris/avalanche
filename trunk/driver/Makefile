include files.make
include ../config.info

OBJECTS := $(addsuffix .o,$(basename $(CPPFILES)))
INSTALL_DIR := $(PREFIX)

all: compile

compile: $(OBJECTS)
	$(CXX) -g -o avalanche $(OBJECTS)

%.o: %.cpp
	$(CXX) -g -Wno-deprecated -c -Iinclude $< -o $*.o

install:
	cp avalanche $(INSTALL_DIR)/bin

clean:
	rm $(OBJECTS) avalanche -rf

