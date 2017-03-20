# Monitoring Benchmark Tooling

This markdown captures the configuration and drivers used to benchmark various aggregation tools.

Tools tested:
* fluentd
* logstash

Tests are generally performed by wiring various driver arrays to the aggregator and testing the aggregator with it
outputting to:

* /dev/null
* disk
* local TCP network target
* remote TCP network target (same VPC/subnet)

Tests were performed using AWS m4.xlarge (4vcpu, 8GB ram, high network performance) instances exclusively. The machine
images used were all Ubuntu Server 16.04 LTS (HVM), SSD Volume Type (ami-16efb076). In cluster tests 4 message
generators were run on each of 3 cloud instances hitting an aggregator on a separate instance (4 instances total).

**Tests Performed:**
//Baseline

1. msg-gen --> local collector (baseline)
2. msg-gen --> remote collector (baseline)

//null suite

4. msg-gen --> local agg
5. msg-gen --> remote agg
6. 12 msg-gen --> remote agg
7. msg-gen --> local agg --net host

//disk suite

8. msg-gen --> local agg
9. msg-gen --> remote agg
10. 12 msg-gen --> remote agg

//local collector net suite

11. msg-gen --> local agg
12. msg-gen --> remote agg
13. 12 msg-gen --> remote agg

//remote collector net suite

14. msg-gen --> local agg
15. msg-gen --> remote agg
16. 12 msg-gen --> remote agg

Message generators are always run with --net=host. Aggregators are run with port mappings. A separate test is done to
compare the performance between port mapping and --net=host aggregators (the net difference is linear in our
experiments).

## C++ Message Generator

The message generator used was a simple C++ application designed to emit a small json message similar to what might be
produced by a sensor monitoring CPU/MEM/DiskIO/etc.

The C++ application was built with the following makefile:

```
user@ubuntu:~/msg-gen$ cat makefile
TARGET = msg-gen msg-con
CLISRC = msg-gen.cpp
CONSRC = msg-con.cpp
CC = g++
CFLAGS = -Wall -std=c++11

all: msg-gen msg-con

msg-gen: $(CLISRC)
	$(CC) -o $@ $(CLISRC) $(CFLAGS) $(LIBS)

msg-con: $(CONSRC)
	$(CC) -o $@ $(CONSRC) $(CFLAGS) $(LIBS)

clean:
	$(RM) $(TARGET)

user@ubuntu:~/msg-gen$
```

The source for the msg-gen.cpp app is as follows:

```c++
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <chrono>
#include <thread>

using namespace std::chrono;

int main(int argc, char * argv[]) {

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
        if (connect(soc, (struct sockaddr * )&target, sizeof(target)) == -1) {
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
                << "\"" << std::setfill('0') << std::setw(10) << counter << std::setw(0) << "\" }]";
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
```

The message generator was packaged into a docker container:

```
user@ubuntu:~/msg-gen$ cat dockerfile
FROM ubuntu:16.04
COPY ./msg-gen /msg-gen
ENTRYPOINT ["/msg-gen"]
CMD ["localhost","-1"]

user@ubuntu:~/msg-gen$ docker build -t randyabernethy/msg-gen .
Sending build context to Docker daemon 43.52 kB
Step 1 : FROM ubuntu:16.04
 ---> 0ef2e08ed3fa
Step 2 : COPY ./msg-gen /msg-gen
 ---> Using cache
 ---> 90aef20c8085
Step 3 : ENTRYPOINT /msg-gen
 ---> Running in 1d912013ae48
 ---> aee8ae78ffae
Removing intermediate container 1d912013ae48
Step 4 : CMD localhost -1
 ---> Running in e5378299fccd
 ---> 88ffdddb3ba0
Removing intermediate container e5378299fccd
Successfully built 88ffdddb3ba0

user@ubuntu:~/msg-gen$
```

The image is available on docker hub:

```
user@ubuntu:~/msg-gen$ docker push randyabernethy/msg-gen
The push refers to a repository [docker.io/randyabernethy/msg-gen]
d6f0f846487b: Pushed
56827159aa8b: Mounted from library/ubuntu
440e02c3dcde: Mounted from library/ubuntu
29660d0e5bb2: Mounted from library/ubuntu
85782553e37a: Mounted from library/ubuntu
745f5be9952c: Mounted from library/ubuntu
latest: digest: sha256:785fdf279762a265481114b5811630b2b3a58e91141f55dff972d2cc908f3b58 size: 1566

user@ubuntu:~/msg-gen$
```


## Message Consumer

The message consumer is a simple C++ TCP server that accept and discards all inbound TCP data. This is used to simulate
aggregator forwarding workflows.

Message consumer code:

```c++
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

int main(int argc, char * argv[]) {
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
        if (bind (soc, (struct sockaddr * ) &name, sizeof (name)) < 0) {
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
            new_soc = accept(soc, (struct sockaddr * )&their_addr, &sin_size);
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
```

The consumer is also packaged into a container:

```
user@ubuntu:~/msg-gen/msg-con-build$ cat dockerfile
FROM ubuntu:16.04
COPY ./msg-con /msg-con
ENTRYPOINT ["/msg-con"]

user@ubuntu:~/msg-gen/msg-con-build$ docker build -t randyabernethy/msg-con .
Sending build context to Docker daemon 30.21 kB
Step 1 : FROM ubuntu:16.04
 ---> 0ef2e08ed3fa
Step 2 : COPY ./msg-con /msg-con
 ---> c12b93c79cbd
Removing intermediate container cb7d7964b48c
Step 3 : ENTRYPOINT /msg-con
 ---> Running in debd64e48716
 ---> fb84f7c4d2d4
Removing intermediate container debd64e48716
Successfully built fb84f7c4d2d4

user@ubuntu:~/msg-gen/msg-con-build$ docker push randyabernethy/msg-con
The push refers to a repository [docker.io/randyabernethy/msg-con]
219ccf4218c5: Pushed
56827159aa8b: Mounted from randyabernethy/msg-gen
440e02c3dcde: Mounted from randyabernethy/msg-gen
29660d0e5bb2: Mounted from randyabernethy/msg-gen
85782553e37a: Mounted from randyabernethy/msg-gen
745f5be9952c: Mounted from randyabernethy/msg-gen
latest: digest: sha256:d003920371dac16137ca14f2625258012de43b453dbde6ff8af7e08934760e77 size: 1565

user@ubuntu:~/msg-gen$ docker run --net=host randyabernethy/msg-con
Server waiting for connections on 9911
Connection, receiving
```


## Fluentd

Fluentd is an open source data collector already in use by the client and the first aggregator tested. The v0.12.32
image from docker hub was used for testing:

```
user@ubuntu:~$ docker pull fluent/fluentd:v0.12.32
v0.12.32: Pulling from fluent/fluentd
0a8490d0dfd3: Pull complete
bba3591bb885: Pull complete
f1228ff8328e: Pull complete
2faef8414df3: Pull complete
b5212ee388b7: Pull complete
0a5b8519a092: Pull complete
317cbe82a1e9: Pull complete
7a7b3e37c7c1: Pull complete
Digest: sha256:fdbaa2b60b5fa812e5bfaff20095d8a73d05521d109e483fb6573dcbe3f34d44
Status: Downloaded newer image for fluent/fluentd:v0.12.32
user@ubuntu:~$
```

The standard container configuration writes all data received on port 24224 to disk logs:

```
user@ubuntu:~$ docker exec -it fd /bin/sh

~ $ ls -l /fluentd/etc/
total 4
-rw-r--r--    1 root     root           676 Feb 18 00:22 fluent.conf

~ $ cat /fluentd/etc/fluent.conf
<source>
  @type  forward
  @id    input1
  @label @mainstream
  port  24224
</source>

<filter **>
  @type stdout
</filter>

<label @mainstream>
  <match docker.**>
    @type file
    @id   output_docker1
    path         /fluentd/log/docker.*.log
    symlink_path /fluentd/log/docker.log
    append       true
    time_slice_format %Y%m%d
    time_slice_wait   1m
    time_format       %Y%m%dT%H%M%S%z
  </match>
  <match **>
    @type file
    @id   output1
    path         /fluentd/log/data.*.log
    symlink_path /fluentd/log/data.log
    append       true
    time_slice_format %Y%m%d
    time_slice_wait   10m
    time_format       %Y%m%dT%H%M%S%z
  </match>
</label>
~ $
```

> Source options:
* type (required) - The value must be forward.
* port - The port to listen to. Default Value = 24224
* bind - The bind address to listen to. Default Value = 0.0.0.0 (all addresses)
* linger_timeout - The timeout time used to set linger option. The default is 0
* chunk_size_limit - The size limit of the the received chunk. If the chunk size is larger than this value, then the received chunk is dropped. The default is nil (no limit).
* chunk_size_warn_limit - The warning size limit of the received chunk. If the chunk size is larger than this value, a warning message will be sent. The default is nil (no warning).
* skip_invalid_event (v0.12.20 or later) - Skip an event if incoming event is invalid. The default is false. This option is useful at forwarder, not aggragator.
* source_hostname_key (v0.12.28 or later) - The field name of the client’s hostname. If set the value, the client’s hostname will be set to its key. The default is nil (no adding hostname). This iterates incoming events. So if you send larger chunks to in_forward, it needs additional processing time.
* log_level - The log_level option allows the user to set different levels of logging for each plugin. The supported log levels are: fatal, error, warn, info, debug, and trace.

A custom configuration was created to add a listener on port 24225 which writes to /dev/null, 24226 which writes to a
local consumer and 24227 which writes to a remote consumer. This configuration is mounted into the container with a
volume mapping at run time:

```
user@ubuntu:~/msg-gen$ cat fluent.conf

  <source>
    @type forward
    @id input1
    @label @mainstream
    port 24224
  </source>
  <source>
    @type forward
    @id input2
    @label @nullstream
    port 24225
  </source>
  <source>
    @type forward
    @id input3
    @label @localstream
    port 24226
  </source>
  <source>
    @type forward
    @id input4
    @label @remotestream
    port 24227
  </source>
  <filter **>
    @type stdout
  </filter>
  <label @mainstream>
    <match **>
      @type file
      @id output1
      path /fluentd/log/data.*.log
      symlink_path /fluentd/log/data.log
      append true
      time_slice_format %Y%m%d
      time_slice_wait 10m
      time_format %Y%m%dT%H%M%S%z
      buffer_path /fluentd/log/data.*.log
    </match>
  </label>
  <label @nullstream>
    <match **>
      @type null
    </match>
  </label>
  <label @localstream>
    <match **>
      @type rawtcp
      host 192.168.131.133
      port 9911
    </match>
  </label>
  <label @remotestream>
    <match **>
      @type rawtcp
      host 192.168.131.134
      port 9911
    </match>
  </label>

user@ubuntu:~/msg-gen$
```


### Custom fluentd TCP plugin

No reliable plugins were found that simply forwarded raw data to a TCP port (tried: out_rawtcp, tcp_client, out_forward,
and others). Forwarders either use a handshake/heartbeat protocol or connect send a chunk and disconnect or both. All
of which greatly limit the maximum throughput possible and poorly align with the nature of metering (loosing a meter
sample is not particularly critical but throughput is).

To solve the problem we created a simple output plugin to forward traffic as raw TCP.

```ruby
module Fluent
  class RawTCPOutput < Fluent::Output
    Fluent::Plugin.register_output("rawtcp", self)

    config_param :host, :string
    config_param :port, :integer, :default => 9911

    def configure(conf)
      @host = conf['host']
      @port = conf['port']
    end

    def start
      super
      @sock = TCPSocket.new(@host, @port)
    end

    def shutdown
      super
      @sock.close rescue nil
      @sock = nil
    end

    def emit(tag, es, chain)
      chain.next
      es.each do |time, record|
        @sock.write("[ \'" + tag + "\", #{time}, " + record.to_json + " ]")
      end
    end
  end
end
```

Custom fluentd docker image with plugin installed:

```
user@ubuntu:~/msg-gen/fluentd$ cat dockerfile
FROM fluent/fluentd:v0.12.32
COPY ./out_rawtcp.rb /etc/fluent/plugin/out_rawtcp.rb

user@ubuntu:~/msg-gen/fluentd$ docker build -t randyabernethy/msg-agg-fd .
Sending build context to Docker daemon 6.656 kB
Step 1 : FROM fluent/fluentd:v0.12.32
 ---> 845c5de3a5c2
Step 2 : COPY ./out_rawtcp.rb /etc/fluent/plugin/out_rawtcp.rb
 ---> 0f89f8948871
Removing intermediate container d6d82ef16ff6
Successfully built 0f89f8948871

user@ubuntu:~/msg-gen/fluentd$ docker push randyabernethy/msg-agg-fd
The push refers to a repository [docker.io/randyabernethy/msg-agg-fd]
f20b9b523d25: Pushed
e3c21dc412b1: Mounted from fluent/fluentd
691225b57abf: Mounted from fluent/fluentd
c48d451de7ee: Mounted from fluent/fluentd
7c6d81758f5b: Mounted from fluent/fluentd
23e250d5a09c: Mounted from fluent/fluentd
41965c68e078: Mounted from fluent/fluentd
8a5375ba8c36: Mounted from fluent/fluentd
60ab55d3379d: Mounted from fluent/fluentd
latest: digest: sha256:b1c6fb0e4b125cb5f72915e9e33542c12160b77eaa4c1d836a26bfaba93a3427 size: 2189

user@ubuntu:~/msg-gen/fluentd$
```



Sample run session:

```
user@ubuntu:~/msg-gen$ docker run --net=host randyabernethy/msg-con


user@ubuntu:~/msg-gen/fluentd$  docker run p 24224-24227:24224-24227 -v ~/data:/fluentd/log -v ~/msg-gen/fluentd/fluent.conf:/fluentd/etc/fluent.conf randyabernethy/msg-agg-fd

2017-03-06 22:23:49 +0000 [info]: reading config file path="/fluentd/etc/fluent.conf"
2017-03-06 22:23:49 +0000 [info]: starting fluentd-0.12.32
2017-03-06 22:23:50 +0000 [info]: gem 'fluentd' version '0.12.32'
2017-03-06 22:23:50 +0000 [info]: adding match in @mainstream pattern="**" type="file"
2017-03-06 22:23:50 +0000 [info]: adding match in @nullstream pattern="**" type="null"
2017-03-06 22:23:50 +0000 [info]: adding match in @localstream pattern="**" type="rawtcp"
2017-03-06 22:23:50 +0000 [info]: adding filter pattern="**" type="stdout"
2017-03-06 22:23:50 +0000 [info]: adding source type="forward"
2017-03-06 22:23:50 +0000 [info]: adding source type="forward"
2017-03-06 22:23:50 +0000 [info]: adding source type="forward"
2017-03-06 22:23:50 +0000 [info]: using configuration file: <ROOT>
  <source>
    @type forward
    @id input1
    @label @mainstream
    port 24224
  </source>
  <source>
    @type forward
    @id input2
    @label @nullstream
    port 24225
  </source>
  <source>
    @type forward
    @id input3
    @label @localstream
    port 24226
  </source>
  <source>
    @type forward
    @id input4
    @label @remotestream
    port 24227
  </source>
  <filter **>
    @type stdout
  </filter>
  <label @mainstream>
    <match **>
      @type file
      @id output1
      path /fluentd/log/data.*.log
      symlink_path /fluentd/log/data.log
      append true
      time_slice_format %Y%m%d
      time_slice_wait 10m
      time_format %Y%m%dT%H%M%S%z
      buffer_path /fluentd/log/data.*.log
    </match>
  </label>
  <label @nullstream>
    <match **>
      @type null
    </match>
  </label>
  <label @localstream>
    <match **>
      @type rawtcp
      host 192.168.131.133
      port 9911
    </match>
  </label>
  <label @remotestream>
    <match **>
      @type rawtcp
      host 192.168.131.134
      port 9911
    </match>
  </label>
</ROOT>
2017-03-06 22:23:50 +0000 [info]: listening fluent socket on 0.0.0.0:24224
2017-03-06 22:23:50 +0000 [info]: listening fluent socket on 0.0.0.0:24225
2017-03-06 22:23:50 +0000 [info]: listening fluent socket on 0.0.0.0:24226
2017-03-06 22:23:50 +0000 [info]: listening fluent socket on 0.0.0.0:24227




user@ubuntu:~/msg-gen/fluentd$ docker run --net=host randyabernethy/msg-gen 192.168.131.133 24226 -1 1
Driving 192.168.131.133:24226 with -1 mpm, sleep(0us)
Msg 1703822: ["msg-gen.pressure", 1488612422, { "cnt":"0001703822" }]

user@ubuntu:~/msg-gen/fluentd$
```

## Logstash

Logstash requires '\n' characters at the end of records when using TCP input and output, failing to send records with
newlines will eventually overflow internal buffers and crash the JVM heap.

The Logstash elemental TCP in/out also adds a significant header to the inbound payload:

- Input: ["msg-gen.pressure", 1488941610, { "cnt":"0000913254"}]
- Output: 2017-03-08T02:53:36.333Z 192.168.131.133 ["msg-gen.pressure", 1488941610, { "cnt":"0000913254"}]

Other than filtering, there is no obvious way to supress this.


### Consumer:

```
user@ubuntu:~/msg-gen/msg-con-build$ docker run --net=host randyabernethy/msg-con
Server waiting for connections on 9911
Connection, receiving
Total bytes 87672384
Last Msg bytes 96
Last Payload: 2017-03-08T02:53:36.333Z 192.168.131.133 ["msg-gen.pressure", 1488941610, { "cnt":"0000913254"}]
Total bytes 95232960
...
```


### Logstash config


Logstash dockerfile:

```
user@ubuntu:~/monitoring/msg-agg/logstash$ cat dockerfile
FROM docker.elastic.co/logstash/logstash:5.2.2
COPY logstash.yml /usr/share/logstash/config/logstash.yml

user@ubuntu:~/monitoring/msg-agg/logstash$
```

A custom Logstash config is added to stop logstash from continually trying to connect to Elasticsearch.

```
user@ubuntu:~/monitoring/msg-agg/logstash$ cat logstash.yml
xpack.monitoring.enabled: false
user@ubuntu:~/monitoring/msg-agg/logstash$
```

Running logstash:

```
user@ubuntu:~/monitoring/msg-agg/logstash$ docker run --net=host -v "$PWD"/pipeline/:/config-dir/  randyabernethy/msg-agg-ls logstash -f /config-dir/conlocal.conf
Sending Logstash's logs to /usr/share/logstash/logs which is now configured via log4j2.properties
[2017-03-08T02:51:37,429][INFO ][logstash.setting.writabledirectory] Creating directory {:setting=>"path.queue", :path=>"/usr/share/logstash/data/queue"}
[2017-03-08T02:51:37,469][INFO ][logstash.agent           ] No persistent UUID file found. Generating new UUID {:uuid=>"b55db196-aba5-475e-a972-e5d8e01bc49d", :path=>"/usr/share/logstash/data/uuid"}
[2017-03-08T02:51:37,787][INFO ][logstash.pipeline        ] Starting pipeline {"id"=>"main", "pipeline.workers"=>2, "pipeline.batch.size"=>125, "pipeline.batch.delay"=>5, "pipeline.max_inflight"=>250}
[2017-03-08T02:51:37,831][INFO ][logstash.inputs.tcp      ] Starting tcp input listener {:address=>"0.0.0.0:24226"}
[2017-03-08T02:51:37,863][INFO ][logstash.pipeline        ] Pipeline main started
[2017-03-08T02:51:38,041][INFO ][logstash.agent           ] Successfully started Logstash API endpoint {:port=>9600}

...
```

### Logstash pipeline configs:

```
user@ubuntu:~/monitoring/msg-agg/logstash/pipeline$ ll
total 24
drwxrwxr-x 2 user user 4096 Mar  7 15:29 ./
drwxrwxr-x 3 user user 4096 Mar  7 18:40 ../
-rw-rw-r-- 1 user user  190 Mar  7 15:29 conlocal.conf
-rw-rw-r-- 1 user user  167 Mar  7 13:39 conremote.conf
-rw-rw-r-- 1 user user  116 Mar  7 13:37 disk.conf
-rw-rw-r-- 1 user user   92 Mar  7 13:38 null.conf
user@ubuntu:~/monitoring/msg-agg/logstash/pipeline$ cat null.conf
input {
  tcp {
    'port' => '24225'
    'mode' => 'server'
  }
}

output {
  null {
  }
}
user@ubuntu:~/monitoring/msg-agg/logstash/pipeline$ cat disk.conf
input {
  tcp {
    'port' => '24224'
    'mode' => 'server'
  }
}

output {
  file {
    'path' => '/msglog'
  }
}
user@ubuntu:~/monitoring/msg-agg/logstash/pipeline$ cat conlocal.conf
input {
  tcp {
    'port' => '24226'
    'mode' => 'server'
    codec => line {
      format => "%{message}"
    }
  }
}

output {
  tcp {
    'host' => '192.168.131.133'
    'port' => '9911'
    'mode' => 'client'
    codec => line {
      format => "%{message}"
    }
  }
}
user@ubuntu:~/monitoring/msg-agg/logstash/pipeline$ cat conremote.conf
input {
  tcp {
    'port' => '24227'
    'mode' => 'server'
  }
}

output {
  tcp {
    'host' => '192.168.131.133'
    'port' => '9911'
    'mode' => 'client'
  }
}
user@ubuntu:~/monitoring/msg-agg/logstash/pipeline$
```


### Message generator:

```
user@ubuntu:~/monitoring/msg-gen$ docker run --net=host randyabernethy/msg-gen 192.168.131.133 24226 -1 1
Driving 192.168.131.133:24226 with -1 mpm, sleep(0us)
Msg 992010: ["msg-gen.pressure", 1488941615, { "cnt":"0000992010"}]

user@ubuntu:~/monitoring/msg-gen$
```


## Statsd

The statsd config prepares statsd to listen on TCP 8124 and UDP 8125.

### Null

To run with null config backend

```
docker run --net=host -v ~/monitoring/msg-agg/statsd/null.js:/statsd/config.js randyabernethy/msg-agg-sd
```

The null config is simple:

```
user@ubuntu:~/monitoring/msg-agg/statsd$ cat null.js
{
  servers: [
    { server: "./servers/tcp", address: "0.0.0.0", port: 8124 },
    { server: "./servers/udp", address: "0.0.0.0", port: 8125 },
  ]
}
user@ubuntu:~/monitoring/msg-agg/statsd$
```


### Disk

To run with json config backend, first create a logging output file on the host (and tail it if you like):

```
user@ubuntu:~/monitoring/msg-agg/statsd$ touch /tmp/statsdlog.json

user@ubuntu:~/monitoring/msg-agg/statsd$ tail -f /tmp/statsdlog.json
{"@timestamp":"2017-03-09T21:33:42.691Z","type":"ubuntu","statsd.bad_lines_seen.count":0,"statsd.packets_received.count":1,"statsd.metrics_received.count":2,"stat-gen.p.cnt.count":1,"stat-gen.p.tme.count":1489095217}
{"@timestamp":"2017-03-09T21:33:51.003Z","type":"ubuntu","statsd.bad_lines_seen.count":0,"statsd.packets_received.count":2,"statsd.metrics_received.count":4,"stat-gen.p.cnt.count":5,"stat-gen.p.tme.count":2978190452,"statsd.timestamp_lag.gauge":-2}
{"@timestamp":"2017-03-09T21:34:01.002Z","type":"ubuntu","statsd.bad_lines_seen.count":0,"statsd.packets_received.count":1,"statsd.metrics_received.count":2,"stat-gen.p.cnt.count":4,"stat-gen.p.tme.count":1489095235,"statsd.timestamp_lag.gauge":0}
{"@timestamp":"2017-03-09T21:34:12.700Z","type":"ubuntu","statsd.bad_lines_seen.count":0,"statsd.packets_received.count":2,"statsd.metrics_received.count":4,"stat-gen.p.cnt.count":11,"stat-gen.p.tme.count":2978190488,"statsd.timestamp_lag.gauge":2}
{"@timestamp":"2017-03-09T21:34:21.007Z","type":"ubuntu","statsd.bad_lines_seen.count":0,"statsd.packets_received.count":1,"statsd.metrics_received.count":2,"stat-gen.p.cnt.count":7,"stat-gen.p.tme.count":1489095255,"statsd.timestamp_lag.gauge":-2}
{"@timestamp":"2017-03-09T21:34:31.003Z","type":"ubuntu","statsd.bad_lines_seen.count":0,"statsd.packets_received.count":2,"statsd.metrics_received.count":4,"stat-gen.p.cnt.count":17,"stat-gen.p.tme.count":2978190528,"statsd.timestamp_lag.gauge":0}
...
```

Run statsd and mount the disk config and mount the file over the statsd log output file:

```
user@ubuntu:~/monitoring/msg-agg/statsd$ docker run --net=host -v ~/monitoring/msg-agg/statsd/disk.js:/statsd/config.js -v /tmp/statsdlog.json:/log/log.json randyabernethy/msg-agg-sd
9 Mar 21:33:31 - [1] reading config file: config.js
9 Mar 21:33:31 - server is up INFO
```

disk config:

```
user@ubuntu:~/monitoring/msg-agg/statsd$ cat disk.js
{
  servers: [
    { server: "./servers/tcp", address: "0.0.0.0", port: 8124 },
    { server: "./servers/udp", address: "0.0.0.0", port: 8125 },
  ],
  backends: ['statsd-json-log-backend'],
  json_log: {
    application: '', // prefix to all the metric names in output [string, default: OS hostname]
    logfile: '/log/log.json'   // file to write the output to [string, default './statsd-log.json' ]
  }
}
user@ubuntu:~/monitoring/msg-agg/statsd$
```


### Network

To run statsd against a consumer use the repeater backend with the address and port of the consumer:

```
user@ubuntu:~/monitoring/msg-agg/statsd$ docker run --net=host -v ~/monitoring/msg-agg/statsd/config.js:/statsd/config.js randyabernethy/msg-agg-sd
9 Mar 21:46:24 - [1] reading config file: config.js
9 Mar 21:46:24 - server is up INFO

```

Network config:

```
user@ubuntu:~/monitoring/msg-agg/statsd$ cat config.js
{
  servers: [
    { server: "./servers/tcp", address: "0.0.0.0", port: 8124 },
    { server: "./servers/udp", address: "0.0.0.0", port: 8125 },
  ],
  backends: ['./backends/repeater'],
  repeater: [{ host: '192.168.131.133', port: 9911}],
  repeaterProtocol: 'tcp'
}
user@ubuntu:~/monitoring/msg-agg/statsd$
```


### Driving statsd

Statsd requires statistics in a particular text format. The stats-gen C++ program was created to drive statsd. It is
exactly like the msg-gen app but with the output line changed to produce:

```
stat-gen.p.cnt:0000000011|c
stat-gen.p.tme:1489095279|c
```

Representing a counter and a timestamp. This is the same data sent by msg-gen and the same number of bytes (56).

Running statsd:

```
user@ubuntu:~/monitoring/stat-gen$ docker run --net=host randyabernethy/stat-gen 192.168.131.133 8124 10 1
Driving 192.168.131.133:8124 with 10 mpm, sleep(6000000us)
Msg 11: stat-gen.p.cnt:0000000011|c
stat-gen.p.tme:1489095279|c

user@ubuntu:~/monitoring/stat-gen$
```


## Telegraf

Building the Telegraf container image:

```
user@ubuntu:~/monitoring/msg-agg/telegraf$ cat dockerfile
FROM golang:1.8.0-alpine

RUN apk update
RUN apk add --no-cache iputils ca-certificates && \
    update-ca-certificates

RUN apk add git make
RUN go get github.com/influxdata/telegraf
WORKDIR $GOPATH/src/github.com/influxdata/telegraf
RUN make

EXPOSE 8125/udp 8092/udp 8094

CMD ["telegraf"]
user@ubuntu:~/monitoring/msg-agg/telegraf$
```

Null config:

```
user@ubuntu:~/monitoring/msg-agg/telegraf$ cat null.conf
[agent]
  interval = "15ms"
  flush_interval = "50ms"
  omit_hostname = true

[[inputs.socket_listener]]
  service_address = "tcp://:8094"
  name_override = "a"
  data_format = "value"
  data_type = "string"

[[outputs.discard]]

user@ubuntu:~/monitoring/msg-agg/telegraf$
```

Local/remote config:

```
user@ubuntu:~/monitoring/msg-agg/telegraf$ cat local.conf
[agent]
  interval = "15ms"
  flush_interval = "50ms"
  omit_hostname = true

[[inputs.socket_listener]]
  service_address = "tcp://:8094"
  name_override = "a"
  data_format = "value"
  data_type = "string"

[[outputs.socket_writer]]
  address = "tcp://192.168.131.133:9911"
  data_format = "json"

user@ubuntu:~/monitoring/msg-agg/telegraf$
```

Running the consumer:

```
user@ubuntu:~/monitoring/msg-agg/telegraf$ docker run --net=host randyabernethy/msg-con
Server waiting for connections on 9911
Connection, receiving

```

Running the Aggregator:

```
user@ubuntu:~/monitoring/msg-agg/telegraf$ docker run -p 8094:8094 -v $PWD/local.conf:/etc/telegraf/telegraf.conf:ro randyabernethy/msg-agg-tg
2017/03/17 01:15:23 I! Using config file: /etc/telegraf/telegraf.conf
2017-03-17T01:15:23Z I! Starting Telegraf (version dev-86-g426182b8)
2017-03-17T01:15:23Z I! Loaded outputs: socket_writer
2017-03-17T01:15:23Z I! Loaded inputs: inputs.socket_listener
2017-03-17T01:15:23Z I! Tags enabled:
2017-03-17T01:15:23Z I! Agent Config: Interval:15ms, Quiet:false, Hostname:"", Flush Interval:50ms

```

Running the generator:

```
user@ubuntu:~/monitoring/msg-agg/telegraf$ docker run --net=host randyabernethy/msg-gen 192.168.131.133 8094 -1 1
Driving 192.168.131.133:8094 with -1 mpm, sleep(0us)
Msg 2194867: ["msg-gen.pressure", 1489711023, { "cnt":"0002194867"}]

user@ubuntu:~/monitoring/msg-agg/telegraf$
```

