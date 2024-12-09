OBJ = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
include ../Rule.mak

all: $(OBJ)
	$(CXX) $^ -o pkcsdemo $(SHLIBS)
$(OBJ): %.o : %.cpp
	$(CXX) -c $< -o $@
clean:
	rm -f pkcsdemo *.o
