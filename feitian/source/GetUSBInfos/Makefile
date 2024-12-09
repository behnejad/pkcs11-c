OBJ = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
include ../Rule.mak

all: $(OBJ)
	$(CXX) $^ -o getusbinfos $(SHLIBS) -ldl
$(OBJ) : %.o : %.cpp
	$(CXX) -c $< -o $@
clean:
	rm  getusbinfos *.o
