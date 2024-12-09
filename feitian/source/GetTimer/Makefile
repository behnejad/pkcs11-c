OBJ = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
include ../Rule.mak
all: $(OBJ)
	$(CXX) $^ -o gettimer $(SHLIBS) -ldl

$(OBJ) : %.o : %.cpp
	   $(CXX) -c $< -o $@
clean:
	rm -f gettimer *.o
