{
  servers: [ 
    { server: "./servers/tcp", address: "0.0.0.0", port: 8124 },
    { server: "./servers/udp", address: "0.0.0.0", port: 8125 },
  ],
  backends: ['./backends/repeater'],
  repeater: [{ host: '192.168.131.133', port: 9911}],
  repeaterProtocol: 'udp4'
}
