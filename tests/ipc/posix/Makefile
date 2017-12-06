MAIN = posix_ipc
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

$(MAIN): $(OBJECTS)
	g++ -Og -lrt -lpthread -std=c++11 $(OBJECTS) -o $(MAIN)

%.o: %.cpp
	g++ -I.. -std=c++11 -g -c -Wall $< -o $@

clean:
	rm -f $(MAIN) $(OBJECTS)
