#include </home/dara/sniffer/headers/ftpf.hpp>
#include </home/dara/sniffer/headers/config.hpp>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
using namespace std;
void insert_ftp(Ftp ftp){
    // cout << "User: "  << ftp.user_s<< endl;
    // cout << "File name: "  << ftp.filename_s<< endl;
    // cout << "File size: "  << ftp.filesize_s<< endl;
    // cout << "Status: "  << ftp.status_s<< endl;
    // cout << "Duration: "  << ftp.time_s<< "\n"<< endl;
   
    try {
        sql::Driver *driver1;
        sql::Connection *con1;
        sql::Statement *stmt1;
        sql::ResultSet *res1;
        sql::PreparedStatement *pstmt1;
        driver1 = get_driver_instance();
        con1 = driver1->connect(address,user,pass);
        con1->setSchema("capture");
        pstmt1 = con1->prepareStatement("INSERT INTO ftp_traffic(timestamp_req,ipv4_client,ipv4_server,port_client,port_server,user,filename,filesize,duration_time,timestamp_res,status) VALUES (?,?,?,?,?,?,?,?,?,?,?);");
        pstmt1->setString(1,ftp.timestamp_req_s);
        pstmt1->setString(2,ftp.ipv4s_s);
        pstmt1->setString(3,ftp.ipv4d_s);
        pstmt1->setInt(4,ftp.sport_s);
        pstmt1->setInt(5,ftp.dport_s);
        pstmt1->setString(6,ftp.user_s);
        pstmt1->setString(7,ftp.filename_s);
        pstmt1->setDouble(8,ftp.filesize_s);
        pstmt1->setDouble(9,ftp.end_s - ftp.begin_s);
        pstmt1->setString(10,ftp.timestamp_res_s);
        pstmt1->setUInt(11,ftp.status_s);
        pstmt1->execute();
        delete pstmt1;
        con1->close();
        delete con1;
        }
    catch (sql::SQLException &e) {
            cout << "# ERR: SQLException in " << __FILE__;
            cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
            cout << "# ERR: " << e.what();
            cout << " (MySQL error code: " << e.getErrorCode();
            cout << ", SQLState: " << e.getSQLState() << " )" << endl;
        }
}
