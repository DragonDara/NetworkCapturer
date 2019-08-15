#include </home/dara/sniffer/headers/imapf.hpp>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
using namespace std;
void insert_imap(Imap imap){
    printf("Req Time: %s",imap.timestamp_req_s);
    cout << "IPv4Src: "  << imap.ipv4s_s<< endl;
    cout << "IPv4Dst: "  << imap.ipv4d_s <<endl; 
    cout << "Source Port: " <<imap.sport_s<<endl;
    cout << "Destination Port: " << imap.dport_s<<endl;
    cout << "to: " <<imap.to_s << endl;
    cout << "from: " <<imap.from_s << endl;
    cout << "subject: " <<imap.subject_s << endl;
    cout << "size: " <<imap.size_s << endl;
    cout << "msg-id: " <<imap.msg_id_s << endl;
    cout << "content-type: " <<imap.content_type_s << endl;
    cout << "file: " <<imap.file_s << endl;
    cout << "in-reply-to: " << imap.inreplyto_s << endl;
    cout << "User-Agent: " << imap.user_agent_s << endl;
    cout << "Return-path: " << imap.returnpath_s<<endl;
    cout << "X-Original-To: " << imap.xoriginalto_s<<endl;
    cout << "Received: " << imap.receive_s<<endl;
    cout << "Number of the message" << imap.number_s << endl;
     
    // try {
    //     sql::Driver *driver2;
    //     sql::Connection *con2;
    //     sql::Statement *stmt2;
    //     sql::ResultSet *res2;
    //     sql::PreparedStatement *pstmt2;
    //     driver2 = get_driver_instance();
    //     con2 = driver2->connect("tcp://192.168.101.16:3306", "dara", "P@$$w0rd");
    //     con2->setSchema("capture");
    //     pstmt2 = con2->prepareStatement("INSERT INTO imap_traffic(timestamp_req,ipv4_client,ipv4_server,port_client,port_server,number_message,timestamp_res,returnpath,received,xoriginalto,from_email,to_email,filename,subject_email,mua,msgid,inreplyto,contenttype) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
    //     pstmt2->setString(1,imap.timestamp_req_s);
    //     pstmt2->setString(2,imap.ipv4s_s);
    //     pstmt2->setString(3,imap.ipv4d_s);
    //     pstmt2->setInt(4,imap.sport_s);
    //     pstmt2->setInt(5,imap.dport_s);
    //     pstmt2->setUInt(6,imap.number_s);
    //     pstmt2->setString(7,imap.timestamp_res_s);
    //     pstmt2->setString(8,imap.returnpath_s);
    //     pstmt2->setString(9,imap.receive_s);
    //     pstmt2->setString(10,imap.xoriginalto_s);
    //     pstmt2->setString(11,imap.from_s);
    //     pstmt2->setString(12,imap.to_s);
    //     pstmt2->setString(13,imap.file_s);
    //     pstmt2->setString(14,imap.subject_s);
    //     pstmt2->setString(15,imap.user_agent_s);
    //     pstmt2->setString(16,imap.msg_id_s);
    //     pstmt2->setString(17,imap.inreplyto_s);
    //     pstmt2->setString(18,imap.content_type_s);
    //     pstmt2->execute();
    //     delete pstmt2;
    //     delete con2;
    //     }
    // catch (sql::SQLException &e) {
    //         cout << "# ERR: SQLException in " << __FILE__;
    //         cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
    //         cout << "# ERR: " << e.what();
    //         cout << " (MySQL error code: " << e.getErrorCode();
    //         cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    // }
}