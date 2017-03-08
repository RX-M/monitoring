#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <chrono>
#include <thread>

using namespace std::chrono;

int main(int argc, char *argv[]) {

    if (! (argc == 4 || argc == 5)) {
        std::cerr << "usage: " << argv[0] << " ip port rate [exit]\n"
                  << ">> rate: is a number representing messages/minute, -1 for max\n"
                  << ">> exit: passing any value in the exit position causes the generator to exit after 1 minute" 
                  << std::endl;
        return 1;
    }

    int soc = -1;
    int result = 0;

    try {
        //SOCKET: Create an IPv4 TCP socket
        soc = socket(AF_INET, SOCK_STREAM, 0);  
        if (soc == -1) {
            throw std::string("failed to create socket");
        }

        //CONNECT: Setup an addr struct with the IP and Port and connect
        struct sockaddr_in target;
        target.sin_addr.s_addr = ::inet_addr(argv[1]);
        target.sin_port = ::htons(std::stoi(argv[2]));
        target.sin_family = AF_INET;
        if (connect(soc, (struct sockaddr *)&target, sizeof(target)) == -1) {
            throw std::string("failed to connect");
        }

        //MASTHEAD: Compute mpm/sleep-time and display
        int mpm = std::stoi(argv[3]);
        int sleep_time_us = 0;
        if (0 < mpm && mpm < 60000001) {
            sleep_time_us = 60000000 / mpm;
        }
        std::cout << "Driving " << argv[1] << ":" << argv[2] << " with " << mpm << " mpm, sleep(" << sleep_time_us << "us)" << std::endl;

        //GENERATE: Send traffic in loop
        int counter = 0;
        std::stringstream buf;
        std::string msg;
        auto start = system_clock::now();
        while (true) {

            //SEND: Increment counter, generate message and send it
            counter++;
            buf.clear();
            buf.str(std::string());
            buf << "[\"msg-gen.pressure\", " 
                << seconds(std::time(NULL)).count()
                << ", { \"cnt\":"
                << "\"" << std::setfill('0') << std::setw(10) << counter << std::setw(0) << "\"}]\n";
            if (send(soc, buf.str().c_str(), buf.str().size(), MSG_NOSIGNAL) == -1) {
                throw std::string("failed to send");
            }

            //LOG: Log once per minute and exit after one minute if flagged to
            auto end = system_clock::now();
            seconds diff = duration_cast<seconds>(end-start);
            if (diff.count() >= 60) {
                start = system_clock::now() + seconds(diff.count() - 60);
                std::cout << "Msg " << counter << ": " << buf.str() << std::endl;
                if (argc == 5) {
                    break;
                }
            }

            //THROTTLE: Throttle output as needed
            if (sleep_time_us > 0) {
                std::this_thread::sleep_for(microseconds(sleep_time_us));
            }
        }
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

    //Shutdown and close the socket
    std::this_thread::sleep_for(seconds(1));
    shutdown(soc, SHUT_RDWR);
    std::this_thread::sleep_for(seconds(1));
    close(soc);

    //Return 0 if sucessful
    return result;
}
