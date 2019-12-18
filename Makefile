all: ./obj/sniff.o ./obj/netstruct.o
	g++ ./obj/sniff.o ./obj/netstruct.o -o ./out/sniff -lpcap -pthread -ldiscpp

./obj/sniff.o: sniff.cpp netstruct.hpp
	g++ -c sniff.cpp -o ./obj/sniff.o

./obj/netstruct.o: netstruct.hpp netstruct.cpp
	g++ -c netstruct.cpp -o ./obj/netstruct.o -I/usr/local/dislin

optim: ./obj/sniff.o ./obj/netstruct.o
	g++ ./obj/sniff.o ./obj/netstruct.o -O0 -g -o ./out/sniff -lpcap -pthread

clean:
	rm -rf ./obj/*.o

