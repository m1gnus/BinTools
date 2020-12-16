CXX = g++
CPPFLAGS = -std=c++14 -Wall -Werror -pedantic -g -O0
LDFLAGS = -lbfd
B_OBJ = loader_demo.o loader.o

.PHONY: clean init_banner end_banner

all: init_banner loader_demo end_banner

init_banner:
	@echo "=== START BUILD ==="

end_banner:
	@echo "===  END BUILD  ==="

loader_demo: $(B_OBJ)
	$(CXX) $(CPPFLAGS) -o loader_demo $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f loader_demo *.o
