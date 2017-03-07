#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>

using namespace std::chrono;
const int bufsiz = 512;

int main(int argc, char *argv[]) {
    int soc = -1;
    int new_soc = -1;
    int result = 0;

    try {
        //SOCKET: Create an IPv4 TCP socket
        int soc = socket (PF_INET, SOCK_STREAM, 0);  
        if (soc == -1) {
            throw std::string("failed to create socket");
        }

        //OPTIONS: Allow port to be reused immediately after app exits 
        int yes=1;
        if (setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            throw std::string("failed to set reuse option");
        }

        //BIND: wire socket to port 9911 on all interfaces
        struct sockaddr_in name;
        name.sin_family = AF_INET;
        name.sin_port = htons (9911);
        name.sin_addr.s_addr = htonl (INADDR_ANY);
        if (bind (soc, (struct sockaddr *) &name, sizeof (name)) < 0) {
            throw std::string("failed to bind socket");
        }

        //LISTEN: accept connections with 1 backlog slot
        if (listen(soc, 1) == -1) {
            throw std::string("failed to listen on socket");
        }

        //ACCEPT LOOP
        do {
            //ACCEPT: accept new connections
            std::cout << "Server waiting for connections on 9911" << std::endl;
            struct sockaddr_storage their_addr;
            socklen_t sin_size = sizeof their_addr;
            new_soc = accept(soc, (struct sockaddr *)&their_addr, &sin_size);
            if (new_soc == -1) {
                throw std::string("accept failed");
            }
            std::cout << "Connection, receiving" << std::endl;

            //OPTIONS: timeout socket reads to display status
            struct timeval timeout;
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
            if (setsockopt(new_soc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                throw std::string("failed to set timeout option");
            }
        
            //RECEIVE LOOP
            std::vector<char> buffer(bufsiz);
            auto start = system_clock::now();
            int total_bytes = 0;
            int recv_size = 0;
            while (true) {
                //RECV: read data, report hang ups, hangs and errors
                recv_size = recv(new_soc, buffer.data(), buffer.capacity(), 0);
                if (recv_size == 0) {
                    close(new_soc);
                    new_soc = -1;
                    std::cout << "socket closed by peer" << std::endl;
                    break;
                } else if (recv_size == -1 && errno == EAGAIN) {
                    //Timeout, loop to allow progress output
                } else if (recv_size < 0) {
                    throw std::string("recv failed");
                } else {
                    total_bytes += recv_size;

                    //LOG: passing a CL arg causes all received data to output
                    if (argc > 1) {
                        std::cout << "Total bytes " << total_bytes << std::endl;
                        std::cout << "Msg bytes: " << recv_size << std::endl;
                        std::cout << "Payload: ";
                        for (int i = 0; i < recv_size && static_cast<unsigned long>(i) < buffer.capacity(); i++) {
                            std::cout << buffer[i];
                        }
                        std::cout << std::endl;
                    }
                }

                //PROGRESS: emit updates every 60 seconds
                auto end = system_clock::now();
                seconds diff = duration_cast<seconds>(end-start);
                if (diff.count() >= 60) {
                    start = system_clock::now() + seconds(diff.count() - 60);
                    std::cout << "Total bytes " << total_bytes << std::endl;
                    std::cout << "Last Msg bytes " << recv_size << std::endl;
                    std::cout << "Last Payload: ";
                    for (int i = 0; i < recv_size && static_cast<unsigned long>(i) < buffer.capacity(); i++) {
                        std::cout << buffer[i];
                    }
                    std::cout << std::endl;
                }
            }
            std::cout << "Total bytes " << total_bytes << std::endl;
        } while (true);
    }
    //INTERNAL ERROR: Report string errors from above code
    catch (const std::string &s) {
        std::cerr << argv[0] << " " << s << ", " << strerror(errno) << std::endl;
        result = errno;
    }
    //EXTERNAL: Report system exceptions
    catch(const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        result = -1;
    }

    //Close sockets
    close(soc);
    close(new_soc);

    //Return 0 on sucess
    return result;
}
