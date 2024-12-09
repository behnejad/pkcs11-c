OBJ := $(patsubst %.cpp,%.o,$(wildcard *.cpp))
include ../Rule.mak
all: $(OBJ)
	$(CXX) $^  $(SHLIBS) -o settokenname -ldl
$(OBJ) : %.o : %.cpp
	$(CXX) -c $< -o $@ 
clean:
	rm -f settokenname *.o
