MAIN = thread_cap
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

$(MAIN): $(OBJECTS)
	g++ -o $(MAIN) -lcap-ng -pthread $(SOURCES) 

%.o: %.cpp
	g++ -std=c++14 -pthread -lcap-ng -g -c -Wall $< -o $@

clean:
	rm -f $(MAIN) $(OBJECTS)

