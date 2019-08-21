#include <tins/tins.h>
#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"
#include "tins/packet.h"
#include "tins/ip_address.h"
#include <iostream>
#include "headers/httpsf.hpp"
#include <sstream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <time.h>
#include <ctime>  
#include <regex>
#include <iterator>
#include <chrono>
#include "headers/httpf.hpp"
#include "headers/ftpf.hpp"
#include "headers/smtpf.hpp"
#include "headers/pop3f.hpp"
#include "headers/imapf.hpp"
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

using namespace Tins;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::TCPIP::Stream;

Smtp smtp;
Http http;
Ftp ftp;
Pop3 pop3;
Https https;
Imap imap;

void eraseAllSubStr(std::string& mainStr, const std::string& toErase)
{
	size_t pos = std::string::npos;

	// Search for the substring in string in a loop untill nothing is found
	while ((pos = mainStr.find(toErase)) != std::string::npos)
	{
		// If found then erase it from string
		mainStr.erase(pos, toErase.length());
	}
}
void eraseSubStringsPre(std::string& mainStr, const std::vector<std::string>& strList)
{
	// Iterate over the given list of substrings. For each substring call eraseAllSubStr() to
	// remove its all occurrences from main string.
	for (std::vector<std::string>::const_iterator it = strList.begin(); it != strList.end(); it++)
	{
		eraseAllSubStr(mainStr, *it);
	}

}

string _asn1string(ASN1_STRING *d)
{
    string asn1_string;
    if (ASN1_STRING_type(d) != V_ASN1_UTF8STRING) {
        unsigned char *utf8;
        int length = ASN1_STRING_to_UTF8( &utf8, d );
        asn1_string= string( (char*)utf8, length );
        OPENSSL_free( utf8 );
    } else { 
        asn1_string= string( (char*)ASN1_STRING_data(d), ASN1_STRING_length(d) );
    }
    return asn1_string;
}
string _subject_as_line(X509_NAME *subj_or_issuer)
{
    BIO * bio_out = BIO_new(BIO_s_mem());
    X509_NAME_print(bio_out,subj_or_issuer,0);
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    string issuer = string(bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
    return issuer;
}
//----------------------------------------------------------------------
std::map<string,string> _subject_as_map(X509_NAME *subj_or_issuer)
{
    std::map<string,string> m;    
    for (int i = 0; i < X509_NAME_entry_count(subj_or_issuer); i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(subj_or_issuer, i);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        ASN1_OBJECT *o = X509_NAME_ENTRY_get_object(e);
        const char* key_name = OBJ_nid2sn( OBJ_obj2nid( o ) );
                m[key_name] = _asn1string(d);
    }
    return m;
}
string subject_one_line(X509* x509)
{
    return _subject_as_line(X509_get_subject_name(x509));
}
std::map<string,string> subject(X509* x509)
{
    return _subject_as_map(X509_get_subject_name(x509));
}
void on_server_data(Stream& stream) {
    string data(stream.server_payload().begin(), stream.server_payload().end());
    time_t my_time = time(NULL); 
    
    regex version_status_regex("([^ ]+) ([\\d]+) ([\\w\\s]+)\r\n");
    regex setcookie_regex("Set-Cookie: ([^\r\n]+)");
    regex contenttype_regex("Content-Type: ([^\r\n]+)");
    regex location_regex("Location: ([^\r\n]+)");
    //boost::regex description_regex("([\\w\\s]+)\r\n");

    bool version_status_valid,description_valid,setcookie_valid,contenttype_valid,location_valid;
    smatch version_status_what, description_what,setcookie_what,contenttype_what,location_what;  

    version_status_valid = regex_search(data,version_status_what,version_status_regex);
    setcookie_valid = regex_search(data,setcookie_what,setcookie_regex);
    contenttype_valid = regex_search(data, contenttype_what, contenttype_regex);
    location_valid = regex_search(data, location_what, location_regex);
    //description_valid = regex_search(data,description_what,description_regex);
    //timestamp_res = ctime(&my_time);
    if (version_status_valid || setcookie_valid || contenttype_valid || location_valid)
    {   
            http.timestamp_res_s =ctime(&my_time);
            http.status_s = version_status_what[2];
            http.description_s = version_status_what[3];
            http.contenttype_s = contenttype_what[1];
            http.location_s = location_what[1];
            http.setcookie_s = setcookie_what[1];
    }
    insert_http(http);
}

void on_client_data(Stream& stream) {
    string data(stream.client_payload().begin(), stream.client_payload().end());
    time_t my_time = time(NULL); 

    regex first_line_regex("([\\w]+) ([^ ]+) ([^ ]*$).+");
    regex cookie_regex("Cookie: ([^\r\n]+)");
    regex referer_regex("Referer: ([^\r\n]+)");
    regex host_regex("Host: ([^\r\n]+)");
    regex accept_regex("Accept: ([^\r\n]+)");
    regex user_agent_regex("User-Agent: ([^\r\n]+)");
    bool first_line_valid,host_valid ,referer_valid,accept_valid,cookie_valid,user_agent_valid;
    smatch first_line_what,host_what,referer_what,accept_what,cookie_what,user_agent_what;
   
    first_line_valid = regex_search(data,first_line_what,first_line_regex);
    referer_valid = regex_search(data,referer_what,referer_regex);
    cookie_valid = regex_search(data,cookie_what,cookie_regex);
    accept_valid = regex_search(data,accept_what,accept_regex);
    host_valid = regex_search(data,host_what,host_regex);
    user_agent_valid = regex_search(data,user_agent_what,user_agent_regex);
    
    if ( first_line_valid || referer_valid || cookie_valid || accept_valid || host_valid || user_agent_valid)
        {   
            http.timestamp_req_s =ctime(&my_time);
            http.ipv4s_s = stream.client_addr_v4().to_string();
            http.ipv4d_s = stream.server_addr_v4().to_string();
            http.sport_s = stream.client_port();
            http.dport_s = stream.server_port();
            http.method_s = first_line_what[1];
            http.http_version_s = first_line_what[3];
            http.host_s = host_what[1];
            http.cookie_s = cookie_what[1];
            http.referer_s = referer_what[1];
         }

  
}

void on_ftp_server_data(Stream& stream){
    string data(stream.server_payload().begin(), stream.server_payload().end());

    regex response_regex("([^ ]+) ([^\r\n]+)");
    regex size_regex(" \\(([0-9]+) bytes\\)\\.");

    bool response_valid,size_valid;
    smatch response_what,size_what;

    // string status, description;
    time_t my_time = time(NULL);
    response_valid = regex_search(data,response_what,response_regex);

    if(response_valid){
        ftp.timestamp_res_s =ctime(&my_time);
        ftp.status_s =  stoi(response_what[1]);//response_what[2] -> description of the status
        string description = response_what[2];
        size_valid = regex_search(description,size_what,size_regex);
        ftp.end_s = my_time;
        if(size_valid){
            ftp.filesize_s = stol(size_what[1]);
        }
    insert_ftp(ftp);
    }
}   

void on_ftp_client_data(Stream& stream){

    string data(stream.client_payload().begin(), stream.client_payload().end());
    string user,retr;
    time_t my_time = time(NULL); 
    regex user_regex("USER ([^\r\n]+)");
    regex retr_regex("RETR ([^\r\n]+)");

    bool user_valid,retr_valid;
    smatch user_what,retr_what;
    
    ftp.ipv4s_s = stream.client_addr_v4().to_string();
    ftp.ipv4d_s = stream.server_addr_v4().to_string();
    ftp.sport_s = stream.client_port();
    ftp.dport_s = stream.server_port();
    user_valid = regex_search(data,user_what,user_regex);
    retr_valid = regex_search(data,retr_what,retr_regex);
    if(user_valid){
        ftp.user_s = user_what[1];
    }
    if(retr_valid){
        ftp.begin_s = my_time;
        ftp.timestamp_req_s = ctime(&my_time);
        ftp.filename_s = retr_what[1];
        stream.server_data_callback(&on_ftp_server_data);
    }
    
}

void on_smtp_server_data(Stream& stream){
    time_t my_time = time(NULL);
    string data(stream.server_payload().begin(), stream.server_payload().end());
    string server;
    regex server_regex("220 ([^\r\n]+)");
    regex response_regex("250 2.0.0 Ok: queued as ([^\r\n]+)");

    smtp.timestamp_res_s =ctime(&my_time);
    bool response_valid, server_valid;
    smatch response_what,server_what;
    server_valid = regex_search(data,server_what,server_regex);
    response_valid = regex_search(data,response_what,response_regex);
    if(server_valid){
        smtp.server_s = server_what[1];
    }
    if(response_valid){
        insert_smtp(smtp);
    }
}

void on_smtp_client_data(Stream& stream){
    time_t my_time = time(NULL);
    string data(stream.client_payload().begin(), stream.client_payload().end());
    regex to_regex("To: ([^\r\n]+)");
    regex from_regex("From: ([^\r\n]+)");
    regex subject_regex("Subject: ([^\r\n]+)");
    regex size_regex(" DATA fragment, ([0-9]+)");
    regex msg_id_regex("Message-ID: ([^\r\n]+)");
    regex content_type_regex("Content-Type: ([^\r\n]+)");
    regex file_regex("filename=\"([^\r\n]+)\"");
    regex inreplyto_regex("In-Reply-To: ([^\r\n]+)");
    regex user_agent_regex("User-Agent: ([^\r\n]+)");
    regex x_mailer_regex("X-Mailer: ([^\r\n]+)");

    string file,content_type;
    bool to_valid,from_valid,subject_valid,msg_id_valid, inreplyto_valid,user_agent_valid,x_mailer_valid;
    smatch to_what,from_what,subject_what,msg_id_what, inreplyto_what,user_agent_what,x_mailer_what; 

    to_valid = regex_search(data, to_what,to_regex);
    from_valid = regex_search(data,from_what,from_regex);
    subject_valid = regex_search(data,subject_what,subject_regex);
    msg_id_valid = regex_search(data,msg_id_what,msg_id_regex);
    inreplyto_valid = regex_search(data,inreplyto_what,inreplyto_regex);
    user_agent_valid = regex_search(data,user_agent_what, user_agent_regex);
    x_mailer_valid = regex_search(data,x_mailer_what,x_mailer_regex);

    if(user_agent_valid){
        //user_agent = boost::lexical_cast<string>(user_agent_what[1]);         
        smtp.user_agent_s = user_agent_what[1];
    }
    if(x_mailer_valid){
        //user_agent = boost::lexical_cast<string>(x_mailer_what[1]);
        smtp.user_agent_s = x_mailer_what[1];
    }
   
    std::regex_iterator<std::string::iterator> it_content (data.begin(), data.end(),content_type_regex);
    std::regex_iterator<std::string::iterator> end_content;
    while (it_content != end_content)
    {
        string result = it_content->str();
        eraseSubStringsPre(result, { "Content-Type:", " " });
        content_type += result;
        ++it_content;
    }
    std::regex_iterator<std::string::iterator> it_file (data.begin(), data.end(),file_regex);
    std::regex_iterator<std::string::iterator> end_file;
    while (it_file != end_file)
    {
        string result = it_file->str();
        eraseSubStringsPre(result, { "filename=", " " });
        file += result;
        ++it_file;
    }
    smtp.timestamp_req_s = ctime(&my_time);
    smtp.ipv4s_s = stream.client_addr_v4().to_string();
    smtp.ipv4d_s = stream.server_addr_v4().to_string();
    smtp.sport_s = stream.client_port();
    smtp.dport_s = stream.server_port();
    if(to_valid || from_valid || subject_valid|| msg_id_valid|| inreplyto_valid || user_agent_valid){
        smtp.to_s = to_what[1];
        smtp.from_s = from_what[1];
        smtp.subject_s = subject_what[1];
        smtp.msg_id_s = msg_id_what[1];
        smtp.inreplyto_s = inreplyto_what[1];
        smtp.content_type_s = content_type;
        smtp.file_s = file;
        //stream.server_data_callback(&on_smtp_server_data);
    }
 
}


void on_imap_server_data(Stream& stream){
    string data(stream.server_payload().begin(), stream.server_payload().end()); 
}


void on_imap_client_data(Stream& stream){
    time_t my_time = time(NULL);
    string data(stream.client_payload().begin(), stream.client_payload().end());
    
}

void on_pop_server_data(Stream& stream){
    time_t my_time = time(NULL);
    string data(stream.server_payload().begin(), stream.server_payload().end());
    string return_path, receive, xoriginalto;

    regex return_path_regex("Return-Path: ([^\r\n]+)");
    regex receive_regex("Received: ([^\r\n]+)");
    regex xoriginalto_regex("X-Original-To: ([^\r\n]+)");
    regex to_regex("To: ([^\r\n]+)");
    regex from_regex("From: ([^\r\n]+)");
    regex subject_regex("Subject: ([^\r\n]+)");
    regex size_regex(" DATA fragment, ([0-9]+)");
    regex msg_id_regex("Message-ID: ([^\r\n]+)");
    regex content_type_regex("Content-Type: ([^\r\n]+)");
    regex file_regex("filename=\"([^\r\n]+)\"");
    regex inreplyto_regex("In-Reply-To: ([^\r\n]+)");
    regex user_agent_regex("User-Agent: ([^\r\n]+)");
    regex x_mailer_regex("X-Mailer: ([^\r\n]+)");

    string file,content_type;
    bool to_valid,from_valid,subject_valid,msg_id_valid, inreplyto_valid,user_agent_valid,x_mailer_valid,return_path_valid, receive_valid,xoriginalto_valid;
    smatch to_what,from_what,subject_what,msg_id_what, inreplyto_what,user_agent_what,x_mailer_what,return_path_what,receive_what,xoriginalto_what; 

    to_valid = regex_search(data, to_what,to_regex);
    from_valid = regex_search(data,from_what,from_regex);
    subject_valid = regex_search(data,subject_what,subject_regex);
    msg_id_valid = regex_search(data,msg_id_what,msg_id_regex);
    inreplyto_valid = regex_search(data,inreplyto_what,inreplyto_regex);
    user_agent_valid = regex_search(data,user_agent_what, user_agent_regex);
    x_mailer_valid = regex_search(data,x_mailer_what,x_mailer_regex);

    if(user_agent_valid){
        //user_agent = boost::lexical_cast<string>(user_agent_what[1]);         
        pop3.user_agent_s = user_agent_what[1];
    }
    if(x_mailer_valid){
        //user_agent = boost::lexical_cast<string>(x_mailer_what[1]);
        pop3.user_agent_s = x_mailer_what[1];
    }
   
    std::regex_iterator<std::string::iterator> it_content (data.begin(), data.end(),content_type_regex);
    std::regex_iterator<std::string::iterator> end_content;
    while (it_content != end_content)
    {
        string result = it_content->str();
        eraseSubStringsPre(result, { "Content-Type:", " " });
        content_type += result;
        ++it_content;
    }
    std::regex_iterator<std::string::iterator> it_file (data.begin(), data.end(),file_regex);
    std::regex_iterator<std::string::iterator> end_file;
    while (it_file != end_file)
    {
        string result = it_file->str();
        eraseSubStringsPre(result, { "filename=", " " });
        file += result;
        ++it_file;
    }

    return_path_valid = std::regex_search(data,return_path_what,return_path_regex);
    receive_valid = std::regex_search(data,receive_what,receive_regex);
    xoriginalto_valid = std::regex_search(data,xoriginalto_what,xoriginalto_regex);


    pop3.timestamp_res_s = ctime(&my_time);
    pop3.ipv4s_s = stream.client_addr_v4().to_string();
    pop3.ipv4d_s = stream.server_addr_v4().to_string();
    pop3.sport_s = stream.client_port();
    pop3.dport_s = stream.server_port();
    if(return_path_valid || receive_valid || xoriginalto_valid || to_valid || from_valid || subject_valid|| msg_id_valid|| inreplyto_valid || user_agent_valid){
        pop3.returnpath_s = return_path_what[1];
        pop3.receive_s = receive_what[1];
        pop3.xoriginalto_s = xoriginalto_what[1];
        pop3.to_s = to_what[1];
        pop3.from_s = from_what[1];
        pop3.subject_s = subject_what[1];
        pop3.msg_id_s = msg_id_what[1];
        pop3.inreplyto_s = inreplyto_what[1];
        pop3.content_type_s = content_type;
        pop3.file_s = file;
        insert_pop3(pop3);
    }
 
}
void on_pop_client_data(Stream& stream){
    time_t my_time = time(NULL);
    string data(stream.client_payload().begin(), stream.client_payload().end());
    regex retr_regex("RETR ([^\r\n]+)");

    smatch retr_what;

    pop3.timestamp_req_s =  ctime(&my_time);
    if(regex_search(data,retr_what,retr_regex)){
        pop3.number_s = stoi(retr_what[1]);
    }
}
void on_https_client_data(Stream& stream){
    time_t my_time = time(NULL);
    string data(stream.client_payload().begin(), stream.client_payload().end());
    cout << "client:" << endl << data << endl;
}
void on_https_server_data(Stream& stream){
    time_t my_time = time(NULL);
    string data(stream.server_payload().begin(), stream.server_payload().end());
    cout << "server:" << endl << data << endl;
}

void on_new_connection(Stream& stream) {

    if(stream.server_port() == 80){
        stream.client_data_callback(&on_client_data);
        stream.server_data_callback(&on_server_data);
    }
    if (stream.server_port() == 21){
        stream.client_data_callback(&on_ftp_client_data);
    }
    if (stream.server_port() == 25){
        stream.client_data_callback(&on_smtp_client_data);
        stream.server_data_callback(&on_smtp_server_data);
    }
    if (stream.server_port() == 443){
        time_t my_time = time(NULL);
        https.timestamp_req_s = ctime(&my_time);
        https.ipv4s_s = stream.client_addr_v4().to_string();
        https.ipv4d_s = stream.server_addr_v4().to_string();
        https.sport_s = stream.client_port();
        https.dport_s = stream.server_port();
        stream.client_data_callback(&on_https_client_data);
        stream.server_data_callback(&on_https_server_data);
        // int sd;
        // struct sockaddr_in addr;
        // BIO *outbio = NULL;
        // SSL_METHOD *method;
        // SSL *ssl;
        // int port = 443;

        // BIO              *certbio = NULL;
        // X509                *cert = NULL;
        // X509_NAME       *certname = NULL;
        
        // OpenSSL_add_all_algorithms();
        // ERR_load_BIO_strings();
        // ERR_load_crypto_strings();
        // SSL_load_error_strings();

        // outbio    = BIO_new(BIO_s_file());
        // outbio    = BIO_new_fp(stdout, BIO_NOCLOSE);
        
        // if(SSL_library_init() < 0){
        //     BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");
        // }

        // SSL_CTX* ctx = SSL_CTX_new (SSLv23_method());
        // SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

        // sd = socket(AF_INET, SOCK_STREAM, 0);
        // memset(&addr, 0, sizeof(addr));
        // addr.sin_family = AF_INET;
        // addr.sin_port = htons(stream.server_port());
        // addr.sin_addr.s_addr = inet_addr(stream.server_addr_v4().to_string().c_str());

        // if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) == -1 ) {
        //     BIO_printf(outbio,"Cannot connect to host %s on port %d.\n", inet_ntoa(addr.sin_addr), port);
        // }

        // ssl = SSL_new(ctx); 
        // SSL_set_fd(ssl, sd);
        // SSL_connect(ssl);
        // cert = SSL_get_peer_certificate(ssl);
        // if (cert == NULL)
        //     printf("Error: Could not get a certificate from: .\n");

        // certname = X509_NAME_new();
        // certname = X509_get_subject_name(cert);
        // X509_NAME_print_ex(outbio, certname, 0, 0);
        // // cout <<"Subject: "    << subject_one_line(cert) << endl;
        // // map<string,string> sfields = subject(cert);
        // // for(map<string, string>::iterator i = sfields.begin(), ix = sfields.end(); i != ix; i++ )
        // // cout << " * " <<  i->first << " : " << i->second << endl;
        // BIO_printf(outbio, "\n\n");
        // //insert_https(https);
        // SSL_free(ssl);
        // close(sd);
        // SSL_CTX_free(ctx);
    }
    // if (stream.server_port() == 143){
    //     stream.client_data_callback(&on_imap_client_data);
    //     stream.server_data_callback(&on_imap_server_data);
    // }
    if (stream.server_port() == 110){
        stream.client_data_callback(&on_pop_client_data);
        stream.server_data_callback(&on_pop_server_data);
    }
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface> <port>" << endl;
        return 1;
    }

   try {

        cout << "Starting capture on interface " << argv[1] << endl;
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("tcp port 21 or 80 or 443 or 25 or 110");
        Sniffer sniffer(argv[1], config);
        StreamFollower follower;
        follower.new_stream_callback(&on_new_connection);
        // Allow following partial TCP streams (e.g. streams that were
        // open before the sniffer started running)
        follower.follow_partial_streams(true);
        // Now strt capturing. Every time there's a new packet, call 
        // follower.process_packet
        sniffer.sniff_loop([&](PDU& packet) {
            follower.process_packet(packet);
            return true;
        });
    }
     catch (std::exception &ex) {
         cerr << "Error_1: " << ex.what() << endl;
         return 1;
     }
}