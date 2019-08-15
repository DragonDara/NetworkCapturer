#include <string>
using std::string;

// #ifndef ADD_H_INCLUDED
// #define ADD_H_INCLUDED
struct Imap{
    char* timestamp_req_s ;
    char* timestamp_res_s ;
    string ipv4s_s;
    string ipv4d_s;
    u_int sport_s;
    u_int dport_s;
    string returnpath_s;
    string xoriginalto_s;
    string receive_s;
    string to_s;
    string from_s;
    string subject_s;
    string size_s;
    string msg_id_s;
    string content_type_s;
    string file_s;
    string inreplyto_s;
    string server_s;
    string user_agent_s;
    u_int number_s;
};
void insert_imap(Imap imap) ;
//#endif // ADD_H_INCLUDED 