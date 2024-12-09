OBJ = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
include ../Rule.mak

all: $(OBJ)
	$(CXX) $^ -o pkcstest $(SHLIBS) -ldl
$(OBJ): %.o : %.cpp
	$(CXX) -c $< -o $@
clean:
	rm -f pkcstest *.o
