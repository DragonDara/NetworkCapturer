include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_INCLUDES)  -c -o main.o pcap++.cpp
	g++ $(PCAPPP_LIBS_DIR) cpp-implementation/httpsi.cpp cpp-implementation/config.cpp -lmysqlcppconn -std=c++11 -static-libstdc++ -o sniff2 main.o $(PCAPPP_LIBS)
	g++ streamdump.cpp cpp-implementation/* -o sniff1 -std=c++11 -lstdc++ -ltins -lmysqlcppconn 

# Clean Target
clean:
	rm main.o sniff1 sniff2
# SSL_LIBRARY_VERSION_2=2
# SSL_LIBRARY_VERSION_3_0=768
# SSL_LIBRARY_VERSION_TLS_1_0=769
# SSL_LIBRARY_VERSION_TLS_1_1=770
# SSL_LIBRARY_VERSION_TLS_1_2=771
# SSL_LIBRARY_VERSION_TLS_1_3=772
#sudo gcc streamdump.cpp cpp-implementation/* -c  -std=c++11 -lstdc++ -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -static-libstdc++ -ltins -lmysqlcppconn -I/usr/local/include/pcapplusplus -I/usr/include/netinet


 