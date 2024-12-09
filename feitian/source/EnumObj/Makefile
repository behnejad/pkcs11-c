OBJ := $(patsubst %.cpp,%.o,$(wildcard *.cpp))
#SHLIBS = ../../../redist/libshuttle_p11v220.so.1.0.0
include ../Rule.mak
all: $(OBJ)
	g++ $^  $(SHLIBS) -o enumobj 
$(OBJ) : %.o : %.cpp
	g++ -c $< -o $@ 
clean:
	rm -f enumobj  *.o
