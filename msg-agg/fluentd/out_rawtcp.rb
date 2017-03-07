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
