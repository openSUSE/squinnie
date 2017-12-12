MAIN = thread_setuid
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

$(MAIN): $(OBJECTS)
	g++ -o $(MAIN) -pthread $(SOURCES) 

%.o: %.cpp
	g++ -std=c++14 -pthread -g -c -Wall $< -o $@

clean:
	rm -f $(MAIN) $(OBJECTS)

