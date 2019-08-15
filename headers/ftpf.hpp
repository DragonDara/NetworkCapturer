#include <string>
using std::string;

// #ifndef ADD_H_INCLUDED
// #define ADD_H_INCLUDED
struct Ftp{
    char* timestamp_req_s ;
    char* timestamp_res_s ;
    string ipv4s_s;
    string ipv4d_s;
    u_int sport_s;
    u_int dport_s;
    string user_s;
    string filename_s;
    u_int status_s;
    long filesize_s;
    long begin_s;
    long end_s;
};
void insert_ftp(Ftp ftp) ;
//#endif // ADD_H_INCLUDED 