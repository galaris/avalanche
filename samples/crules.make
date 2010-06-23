CC:= gcc

OBJECTS := $(addsuffix ,$(basename $(SOURCES)))

all: compile

compile: $(OBJECTS)

%.o : %.c
	$(CC) -g -c $< -o $@

%.o : %.cpp
	$(CXX) -g -c $< -o $@

clean:
	rm -rf $(OBJECTS) entry

.PHONY: all compile link clean
