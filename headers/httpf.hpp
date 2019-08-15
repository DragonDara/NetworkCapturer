#include <string>
using std::string;

// #ifndef ADD_H_INCLUDED
// #define ADD_H_INCLUDED
struct Http{
    char* timestamp_req_s;
    string ipv4s_s;
    string ipv4d_s;
    u_int sport_s;
    u_int dport_s;
    string method_s;
    string http_version_s;
    string host_s;
    string cookie_s;
    string referer_s;
    char* timestamp_res_s;
    string status_s;
    string description_s;
    string contenttype_s;
    string location_s;
    string setcookie_s;
};
void insert_http(Http http) ;
//#endif // ADD_H_INCLUDED 