#include </home/dara/sniffer/headers/pop3f.hpp>
#include </home/dara/sniffer/headers/config.hpp>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
using namespace std;
void insert_pop3(Pop3 pop3){
    // printf("Req Time: %s",pop3.timestamp_req_s);
    // cout << "IPv4Src: "  << pop3.ipv4s_s<< endl;
    // cout << "IPv4Dst: "  << pop3.ipv4d_s <<endl; 
    // cout << "Source Port: " <<pop3.sport_s<<endl;
    // cout << "Destination Port: " << pop3.dport_s<<endl;
    // cout << "to: " <<pop3.to_s << endl;
    // cout << "from: " <<pop3.from_s << endl;
    // cout << "subject: " <<pop3.subject_s << endl;
    // cout << "size: " <<pop3.size_s << endl;
    // cout << "msg-id: " <<pop3.msg_id_s << endl;
    // cout << "content-type: " <<pop3.content_type_s << endl;
    // cout << "file: " <<pop3.file_s << endl;
    // cout << "in-reply-to: " << pop3.inreplyto_s << endl;
    // cout << "User-Agent: " << pop3.user_agent_s << endl;
    // cout << "Return-path: " << pop3.returnpath_s<<endl;
    // cout << "X-Original-To: " << pop3.xoriginalto_s<<endl;
    // cout << "Received: " << pop3.receive_s<<endl;
    // cout << "Number of the message" << pop3.number_s << endl;
     
    try {
        sql::Driver *driver2;
        sql::Connection *con2;
        sql::Statement *stmt2;
        sql::ResultSet *res2;
        sql::PreparedStatement *pstmt2;
        driver2 = get_driver_instance();
        con2 = driver2->connect(address,user,pass);
        con2->setSchema("capture");
        pstmt2 = con2->prepareStatement("INSERT INTO pop3_traffic(timestamp_req,ipv4_client,ipv4_server,port_client,port_server,number_message,timestamp_res,returnpath,received,xoriginalto,from_email,to_email,filename,subject_email,mua,msgid,inreplyto,contenttype) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
        pstmt2->setString(1,pop3.timestamp_req_s);
        pstmt2->setString(2,pop3.ipv4s_s);
        pstmt2->setString(3,pop3.ipv4d_s);
        pstmt2->setInt(4,pop3.sport_s);
        pstmt2->setInt(5,pop3.dport_s);
        pstmt2->setUInt(6,pop3.number_s);
        pstmt2->setString(7,pop3.timestamp_res_s);
        pstmt2->setString(8,pop3.returnpath_s);
        pstmt2->setString(9,pop3.receive_s);
        pstmt2->setString(10,pop3.xoriginalto_s);
        pstmt2->setString(11,pop3.from_s);
        pstmt2->setString(12,pop3.to_s);
        pstmt2->setString(13,pop3.file_s);
        pstmt2->setString(14,pop3.subject_s);
        pstmt2->setString(15,pop3.user_agent_s);
        pstmt2->setString(16,pop3.msg_id_s);
        pstmt2->setString(17,pop3.inreplyto_s);
        pstmt2->setString(18,pop3.content_type_s);
        pstmt2->execute();
        delete pstmt2;
        delete con2;
        }
    catch (sql::SQLException &e) {
            cout << "# ERR: SQLException in " << __FILE__;
            cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
            cout << "# ERR: " << e.what();
            cout << " (MySQL error code: " << e.getErrorCode();
            cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    }
}