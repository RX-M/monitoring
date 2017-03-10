var util = require('util');
var os = require('os');
var fs = require('fs');

function RawLogBackend(startupTime, config, emitter, logger){
  var self = this;
  this.targetFile = this.config.logfile || './raw.log';
  emitter.on('packet', function(packet, rinfo) { self.emit(packet, rinfo); });
}

RawLogBackend.prototype.emit = function(packet, rinfo) {

  fs.appendFile(this.targetFile, packet.toString(), function(err) {
    if(err) return false;
  });

  return true;
};

exports.init = function(startupTime, config, emitter, logger) {
  var instance = new RawLogBackend(startupTime, config, emitter);
  return true;
};
