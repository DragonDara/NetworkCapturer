#include </home/dara/sniffer/headers/httpsf.hpp>
#include </home/dara/sniffer/headers/config.hpp>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
using namespace std;

void insert_https(Https https){
    // printf("Req Time: %s\n",https.timestamp_req_s);
    // cout << "IPv4Src: "  << https.ipv4s_s<< endl;
    // cout << "IPv4Dst: "  <<https.ipv4d_s <<endl; 
    // cout << "Source Port: " << https.sport_s<<endl;
    // cout << "Destination Port: " << https.dport_s<<endl;
    // cout << "SNI: "  <<https.hostname_s <<endl; 
    // cout << "Version: " << https.version_s<<endl;
    // cout << "Cipher: " << https.cipher_s<<endl;
    // // cout << "Method: "<<https.url_s << endl; 
    try {
        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        sql::PreparedStatement *pstmt;

        /* Create a connection */
        driver = get_driver_instance();
        con = driver->connect(address, user, pass);
        /* Connect to the MySQL test database */
        con->setSchema("capture");
        pstmt = con->prepareStatement("INSERT INTO https_traffic(timestamp_req,ipv4_client,ipv4_server,port_client,port_server,hostname,version,cipher) VALUES (?,?,?,?,?,?,?,?);");
        pstmt->setString(1,https.timestamp_s);
        pstmt->setString(2,https.ipv4s_s);
        pstmt->setString(3,https.ipv4d_s);
        pstmt->setInt(4,https.sport_s);
        pstmt->setInt(5,https.dport_s);
        pstmt->setString(6,https.hostname_s);
        pstmt->setString(7,https.version_s);
        pstmt->setString(8,https.cipher_s);
        pstmt->execute();
        delete pstmt;
        con->close();
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