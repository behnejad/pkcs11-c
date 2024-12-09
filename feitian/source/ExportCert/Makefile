OBJ = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
include ../Rule.mak

all: $(OBJ)
	$(CXX) $^ -o exportcert $(SHLIBS)

$(OBJ): %.o: %.cpp
	$(CXX) -c $< -o $@
clean:
	rm -f *.o exportcert
