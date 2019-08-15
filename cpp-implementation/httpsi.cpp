#include </home/dara/sniffer/headers/httpsf.hpp>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
using namespace std;

void insert_https(Https https){
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
        pstmt = con->prepareStatement("INSERT INTO https_traffic(timestamp_req,ipv4_client,ipv4_server,port_client,port_server) VALUES (?,?,?,?,?);");
        pstmt->setString(1,https.timestamp_req_s);
        pstmt->setString(2,https.ipv4s_s);
        pstmt->setString(3,https.ipv4d_s);
        pstmt->setInt(4,https.sport_s);
        pstmt->setInt(5,https.dport_s);
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