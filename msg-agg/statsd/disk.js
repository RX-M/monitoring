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
