#include </home/dara/sniffer/headers/smtpf.hpp>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
using namespace std;

void insert_smtp(Smtp smtp){
    printf("Req Time: %s",smtp.timestamp_req_s);
    cout << "IPv4Src: "  << smtp.ipv4s_s<< endl;
    cout << "IPv4Dst: "  << smtp.ipv4d_s <<endl; 
    cout << "Source Port: " << smtp.sport_s<<endl;
    cout << "Destination Port: " << smtp.dport_s<<endl;
    cout << "to: " <<smtp.to_s << endl;
    cout << "from: " <<smtp.from_s << endl;
    cout << "subject: " <<smtp.subject_s << endl;
    cout << "size: " <<smtp.size_s << endl;
    cout << "msg-id: " <<smtp.msg_id_s << endl;
    cout << "content-type: " <<smtp.content_type_s << endl;
    cout << "file: " <<smtp.file_s << endl;
    cout << "in-reply-to: " << smtp.inreplyto_s << endl;
    cout << "MTA: " << smtp.server_s << endl;
    cout << "User-Agent: " << smtp.user_agent_s << endl;
     
    try {
        sql::Driver *driver2;
        sql::Connection *con2;
        sql::Statement *stmt2;
        sql::ResultSet *res2;
        sql::PreparedStatement *pstmt2;
        driver2 = get_driver_instance();
        con2 = driver2->connect("tcp://192.168.101.16:3306", "dara", "P@$$w0rd");
        con2->setSchema("capture");
        pstmt2 = con2->prepareStatement("INSERT INTO smtp_traffic(timestamp_req,ipv4_client,ipv4_server,port_client,port_server,from_email,to_email,size,subject_email,msgid,inreplyto,contenttype,filename,mua,timestamp_res,mta) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
        pstmt2->setString(1,smtp.timestamp_req_s);
        pstmt2->setString(2,smtp.ipv4s_s);
        pstmt2->setString(3,smtp.ipv4d_s);
        pstmt2->setInt(4,smtp.sport_s);
        pstmt2->setInt(5,smtp.dport_s);
        pstmt2->setString(6,smtp.from_s);
        pstmt2->setString(7,smtp.to_s);
        pstmt2->setString(8,smtp.size_s);
        pstmt2->setString(9,smtp.subject_s);
        pstmt2->setString(10,smtp.msg_id_s);
        pstmt2->setString(11,smtp.inreplyto_s);
        pstmt2->setString(12,smtp.content_type_s);
        pstmt2->setString(13,smtp.file_s);
        pstmt2->setString(14,smtp.user_agent_s);
        pstmt2->setString(15,smtp.timestamp_res_s);
        pstmt2->setString(16,smtp.server_s);
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