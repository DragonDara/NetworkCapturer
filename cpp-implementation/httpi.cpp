#include </home/dara/sniffer/headers/httpf.hpp>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
using namespace std;

void insert_http(Http http){
    // printf("Req Time: %s",http_req_res.timestamp_req_s);
    // cout << "IPv4Src: "  << http_req_res.ipv4s_s<< endl;
    // cout << "IPv4Dst: "  <<http_req_res.ipv4d_s <<endl; 
    // cout << "Source Port: " << http_req_res.sport_s<<endl;
    // cout << "Destination Port: " << http_req_res.dport_s<<endl;
    // cout << "Method: "<<http_req_res.method_s << endl; 
    // cout << "Host: "<<http_req_res.host_s<< endl;
    // cout << "Referer: "<<http_req_res.referer_s<<endl;
    // cout << "Cookie: "<<http_req_res.cookie_s<<endl;
    // printf("Res Time: %s",http_req_res.timestamp_res_s);
    // cout << "Status: "<<http_req_res.status_s<< endl;
    // cout << "Content-Type: "<<http_req_res.contenttype_s<< endl;
    // cout << "Location: "<<http_req_res.location_s<< endl;
    // cout << "Description: "<<http_req_res.description_s<<"\n"<<endl;
    try {
        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        sql::PreparedStatement *pstmt;

        /* Create a connection */
        driver = get_driver_instance();
        con = driver->connect("tcp://192.168.101.16:3306", "dara", "P@$$w0rd");
        /* Connect to the MySQL test database */
        con->setSchema("capture");
        pstmt = con->prepareStatement("INSERT INTO http_traffic(timestamp_req,ipv4_client,ipv4_server,port_client,port_server,action,version,host,cookie,referer,timestamp_res,status,description,location,content_type,setcookie) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
        pstmt->setString(1,http.timestamp_req_s);
        pstmt->setString(2,http.ipv4s_s);
        pstmt->setString(3,http.ipv4d_s);
        pstmt->setInt(4,http.sport_s);
        pstmt->setInt(5,http.dport_s);
        pstmt->setString(6,http.method_s);
        pstmt->setString(7,http.http_version_s);
        pstmt->setString(8,http.host_s);
        pstmt->setString(9,http.cookie_s);
        pstmt->setString(10,http.referer_s);
        pstmt->setString(11,http.timestamp_res_s);
        pstmt->setString(12,http.status_s);
        pstmt->setString(13,http.description_s);
        pstmt->setString(14,http.location_s);
        pstmt->setString(15,http.contenttype_s);
        pstmt->setString(16,http.setcookie_s);
        pstmt->execute();
        delete pstmt;
        delete con;
    }
    catch (sql::SQLException &e) {
        cout << "# ERR: SQLException in " << __FILE__;
        cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
        cout << "# ERR: " << e.what();
        cout << " (MySQL error code: " << e.getErrorCode();
        cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    }

}