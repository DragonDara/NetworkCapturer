#include <string>
using std::string;

// #ifndef ADD_H_INCLUDED
// #define ADD_H_INCLUDED
struct Https{
    char* timestamp_req_s;
    string ipv4s_s;
    string ipv4d_s;
    u_int sport_s;
    u_int dport_s;
    string url_s;
};
void insert_https(Https https) ;
//#endif // ADD_H_INCLUDED 