sniff: ./obj/sniff.o ./obj/netstruct.o
	g++ ./obj/sniff.o ./obj/netstruct.o -o ./out/sniff -lpcap -pthread

./obj/sniff.o: sniff.cpp netstruct.hpp
	g++ -c sniff.cpp -o ./obj/sniff.o

./obj/netstruct.o: netstruct.hpp netstruct.cpp
	g++ -c netstruct.cpp -o ./obj/netstruct.o

clean:
	rm -rf ./obj/*.o

