require 'thread'
require 'forwardable'
require 'pp'
module Net
  module SNMP
    # Provides an API for managing SNMP agents
    class Session
      extend Forwardable
      include Net::SNMP::Debug
      attr_accessor :struct, :callback, :requests, :peername, :port, :community
      attr_reader :version
      def_delegator :@struct, :pointer
      @lock = Mutex.new
      @sessions = {}

      class << self
        attr_accessor :sessions, :lock

        # Open a new session.  Accepts a block which yields the session.
        #
        #   Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'public') do |sess|
        #     pdu = sess.get(["sysDescr.0"])
        #     pdu.print
        #   end
        #
        # Arguments
        # - options: A Hash or String object
        #   + As a Hash, supports the following keys
        #     - peername: hostname
        #     - community: snmp community string.  Default is public
        #     - version: snmp version.  Possible values include 1, '2c', and 3. Default is 1.
        #     - timeout: snmp timeout in seconds
        #     - retries: snmp retries.  default = 5
        #     - security_level: SNMPv3 only. default = Net::SNMP::Constants::SNMP_SEC_LEVEL_NOAUTH
        #     - auth_protocol: SNMPv3 only. default is nil (usmNoAuthProtocol). Possible values include :md5, :sha1, and nil
        #     - priv_protocol: SNMPv3 only. default is nil (usmNoPrivProtocol). Possible values include :des, :aes, and nil
        #     - context: SNMPv3 only.
        #     - username: SNMPv3 only.
        #     - auth_password: SNMPv3 only.
        #     - priv_password: SNMPv3 only.
        #
        # Returns a new Net::SNMP::Session
        def open(options = {})
          session = new(options)
          if Net::SNMP::thread_safe
            Net::SNMP::Session.lock.synchronize {
              Net::SNMP::Session.sessions[session.sessid] = session
            }
          else
            Net::SNMP::Session.sessions[session.sessid] = session
          end
          if block_given?
            yield session
          end
          session
        end
      end

      def initialize(options = {})
        options = {:peername => options} if options.kind_of?(String)
        @timeout = options[:timeout] || 1
        @retries = options[:retries] || 5
        @requests = {}
        @peername = options[:peername] || 'localhost'
        # If the port is supplied in the peername, don't
        # worry about the port option (avoids appending two port numbers)
        unless @peername[':']
          options[:port] ||= 161
          @port = options[:port]
          @peername = "#{@peername}:#{options[:port]}"
        end
        @community = options[:community] || "public"
        options[:community_len] = @community.length
        options[:version] ||= Constants::SNMP_VERSION_2c
        @version = options[:version]
        @sess = Wrapper::SnmpSession.new(nil)
        Wrapper.snmp_sess_init(@sess.pointer)
        @sess.community = FFI::MemoryPointer.from_string(@community)
        @sess.community_len = @community.length
        @sess.peername = FFI::MemoryPointer.from_string(@peername)
        @sess.version = case @version.to_s
        when '1'
          Constants::SNMP_VERSION_1
        when '2', '2c'
          Constants::SNMP_VERSION_2c
        when '3'
          Constants::SNMP_VERSION_3
        else
          Constants::SNMP_VERSION_1
        end
        @sess.timeout = @timeout * 1000000
        @sess.retries = @retries

        if @sess.version == Constants::SNMP_VERSION_3
          @sess.securityLevel = options[:security_level] || Constants::SNMP_SEC_LEVEL_NOAUTH
          @sess.securityAuthProto = case options[:auth_protocol]
              when :sha1
                OID.new("1.3.6.1.6.3.10.1.1.3").pointer
              when :md5
                OID.new("1.3.6.1.6.3.10.1.1.2").pointer
              when nil
                OID.new("1.3.6.1.6.3.10.1.1.1").pointer
          end
          @sess.securityPrivProto = case options[:priv_protocol]
              when :aes
                OID.new("1.3.6.1.6.3.10.1.2.4").pointer
              when :des
                OID.new("1.3.6.1.6.3.10.1.2.2").pointer
              when nil
                OID.new("1.3.6.1.6.3.10.1.2.1").pointer
          end

          @sess.securityAuthProtoLen = 10
          @sess.securityAuthKeyLen = Constants::USM_AUTH_KU_LEN

          @sess.securityPrivProtoLen = 10
          @sess.securityPrivKeyLen = Constants::USM_PRIV_KU_LEN


          if options[:context]
            @sess.contextName = FFI::MemoryPointer.from_string(options[:context])
            @sess.contextNameLen = options[:context].length
          end

          # Do not generate_Ku, unless we're Auth or AuthPriv
          unless @sess.securityLevel == Constants::SNMP_SEC_LEVEL_NOAUTH
            options[:auth_password] ||= options[:password]  # backward compatability
            if options[:username].nil? or options[:auth_password].nil?
              raise Net::SNMP::Error.new "SecurityLevel requires username and password"
            end
            if options[:username]
              @sess.securityName = FFI::MemoryPointer.from_string(options[:username])
              @sess.securityNameLen = options[:username].length
            end

            auth_len_ptr = FFI::MemoryPointer.new(:size_t)
            auth_len_ptr.write_int(Constants::USM_AUTH_KU_LEN)
            auth_key_result = Wrapper.generate_Ku(@sess.securityAuthProto,
                                             @sess.securityAuthProtoLen,
                                             options[:auth_password],
                                             options[:auth_password].length,
                                             @sess.securityAuthKey,
                                             auth_len_ptr)
            @sess.securityAuthKeyLen = auth_len_ptr.read_int

            if @sess.securityLevel == Constants::SNMP_SEC_LEVEL_AUTHPRIV
              priv_len_ptr = FFI::MemoryPointer.new(:size_t)
              priv_len_ptr.write_int(Constants::USM_PRIV_KU_LEN)

              # NOTE I know this is handing off the AuthProto, but generates a proper
              # key for encryption, and using PrivProto does not.
              priv_key_result = Wrapper.generate_Ku(@sess.securityAuthProto,
                                               @sess.securityAuthProtoLen,
                                               options[:priv_password],
                                               options[:priv_password].length,
                                               @sess.securityPrivKey,
                                               priv_len_ptr)
              @sess.securityPrivKeyLen = priv_len_ptr.read_int
            end

            unless auth_key_result == Constants::SNMPERR_SUCCESS and priv_key_result == Constants::SNMPERR_SUCCESS
              Wrapper.snmp_perror("netsnmp")
            end
          end
        end

        @struct = Wrapper.snmp_sess_open(@sess.pointer)
      end

      # Close the snmp session and free associated resources.
      def close
        if Net::SNMP.thread_safe
          Session.lock.synchronize {
            Wrapper.snmp_sess_close(@struct)
            Session.sessions.delete(self.sessid)
          }
        else
          Wrapper.snmp_sess_close(@struct)
          Session.sessions.delete(self.sessid)
        end
      end

      # Issue an SNMP GET Request.
      # See #send_pdu
      def get(oidlist, options = {}, &block)
        pdu = PDU.new(Constants::SNMP_MSG_GET)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        send_pdu(pdu, options, &block)
      end

      # Issue an SNMP GETNEXT Request
      # See #send_pdu
      def get_next(oidlist, options = {}, &block)
        pdu = PDU.new(Constants::SNMP_MSG_GETNEXT)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        send_pdu(pdu, options, &block)
      end

      # Issue an SNMP GETBULK Request
      # Supports typical options, plus
      #  - `:non_repeaters` The number of non-repeated oids in the request
      #  - `:max_repititions` The maximum repititions to return for all repeaters
      # Note that the non-repeating varbinds must be added first.
      # See #send_pdu
      def get_bulk(oidlist, options = {}, &block)
        pdu = PDU.new(Constants::SNMP_MSG_GETBULK)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        pdu.non_repeaters = options[:non_repeaters] || 0
        pdu.max_repetitions = options[:max_repetitions] || 10
        send_pdu(pdu, options, &block)
      end

      # Issue an SNMP Set Request.
      # - vb_list: An single varbind, or an array of varbinds, each of which may be
      #   + An Array of length 3 `[oid, type, value]`
      #   + An Array of length 2 `[oid, value]`
      #   + Or a Hash `{oid: oid, type: type, value: value}`
      #     * Hash syntax is the same as supported by PDU.add_varbind
      #     * If type is not supplied, it is infered by the value
      # See #send_pdu
      def set(vb_list, options = {}, &block)
        pdu = PDU.new(Constants::SNMP_MSG_SET)

        # Normalize input to an array if a single varbind is supplied
        if vb_list.kind_of?(Hash) || (vb_list.kind_of?(Enumerable) && !vb_list.first.kind_of?(Enumerable))
          vb_list = [vb_list]
        end

        vb_list.each do |vb|
          if vb.kind_of?(Hash)
            pdu.add_varbind(vb)
          elsif vb.kind_of?(Enumerable) && vb.length == 3
            pdu.add_varbind(:oid => vb[0], :type => vb[1], :value => vb[2])
          elsif vb.kind_of?(Enumerable) && vb.length == 2
            pdu.add_varbind(:oid => vb[0], :value => vb[1])
          else
            raise "Invalid varbind: #{vb}"
          end
        end
        send_pdu(pdu, options, &block)
      end

      # Proxy getters to the C struct representing the session
      def method_missing(m, *args)
        if @struct.respond_to?(m)
          @struct.send(m, *args)
        else
          super
        end
      end

      def default_max_repeaters
        # We could do something based on transport here.  25 seems safe
        25
      end

      # Raise a NET::SNMP::Error with the session attached
      def error(msg, options = {})
        #Wrapper.snmp_sess_perror(msg, @sess.pointer)
        err =  Error.new({:session => self}.merge(options))
        raise err, msg
      end


      # Check the session for SNMP responses from asynchronous SNMP requests
      # This method will check for new responses and call the associated
      # response callbacks.
      # +timeout+  A timeout of nil indicates a poll and will return immediately.
      # A value of false will block until data is available.  Otherwise, pass
      # the number of seconds to block.
      # Returns the number of file descriptors handled.
      def select(timeout = nil)
        unless @fdset
          # 8K should be plenty of space
          @fdset = FFI::MemoryPointer.new(1024 * 8)
        end

        @fdset.clear

        num_fds = FFI::MemoryPointer.new(:int)
        tv_sec = timeout ? timeout.round : 0
        tv_usec = timeout ? (timeout - timeout.round) * 1000000 : 0
        tval = Wrapper::TimeVal.new(:tv_sec => tv_sec, :tv_usec => tv_usec)
        block = FFI::MemoryPointer.new(:int)
        if timeout.nil?
          block.write_int(0)
        else
          block.write_int(1)
        end

        Wrapper.snmp_sess_select_info(@struct, num_fds, @fdset, tval.pointer, block )
        tv = (timeout == false ? nil : tval)
        num_ready = FFI::LibC.select(num_fds.read_int, @fdset, nil, nil, tv)
        if num_ready > 0
          Wrapper.snmp_sess_read(@struct, @fdset)
        elsif num_ready == 0
          Wrapper.snmp_sess_timeout(@struct)
        elsif num_ready == -1
          # error.  check snmp_error?
          error("select")
        else
          error("wtf is wrong with select?")
        end
        num_ready
      end

      alias :poll :select

      # Issue repeated getnext requests on each oid passed in until
      # the result is no longer a child.  Returns a hash with the numeric
      # oid strings as keys.
      # XXX work in progress.   only works synchronously (except with EM + fibers).
      # Need to do better error checking and use getbulk when avaiable.
      def walk(oidlist, options = {})
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist = oidlist.map {|o| o.kind_of?(OID) ? o : OID.new(o)}
        all_results = {}
        base_list = oidlist
        while(!oidlist.empty? && pdu = get_next(oidlist, options))
          debug "================ Walk: Get Next ====================="
          debug "base_list: \n#{base_list.map { |o| "   - #{o.to_s}" }.join("\n")}"
          prev_base = base_list.dup
          oidlist = []
          pdu.varbinds.each_with_index do |vb, i|
            if prev_base[i].parent_of?(vb.oid) && vb.object_type != Constants::SNMP_ENDOFMIBVIEW
              # Still in subtree.  Store results and add next oid to list
              debug "adding #{vb.oid} to oidlist"
              all_results[vb.oid.to_s] = vb.value
              oidlist << vb.oid
            else
              # End of subtree.  Don't add to list or results
              debug "End of subtree"
              base_list.delete_at(i)
              debug "not adding #{vb.oid}"
            end
            # If get a pdu error, we can only tell the first failing varbind,
            # So we remove it and resend all the rest
            if pdu.error? && pdu.errindex == i + 1
              oidlist.pop  # remove the bad oid
              debug "Error on: #{pdu.varbinds[pdu.errindex - 1].oid}"
              if pdu.varbinds.size > i+1
                # recram rest of oids on list
                ((i+1)..pdu.varbinds.size).each do |j|
                  debug "j = #{j}"
                  debug "adding #{j} = #{prev_list[j]}"
                  oidlist << prev_list[j]
                end
                # delete failing oid from base_list
                base_list.delete_at(i)
              end
              break
            end
          end
        end
        if block_given?
          yield all_results
        end
        all_results
      end

      # Given a list of columns (e.g ['ifIndex', 'ifDescr'], will return a hash with
      # the indexes as keys and hashes as values.
      #   puts sess.get_columns(['ifIndex', 'ifDescr']).inspect
      #   {'1' => {'ifIndex' => '1', 'ifDescr' => 'lo0'}, '2' => {'ifIndex' => '2', 'ifDescr' => 'en0'}}
      def columns(columns, options = {})
        columns = columns.map {|c| c.kind_of?(OID) ? c : OID.new(c)}
        walk_hash = walk(columns, options)
        results = {}
        walk_hash.each do |k, v|
          oid = OID.new(k)
          results[oid.index] ||= {}
          results[oid.index][oid.node.label] = v
        end
        if block_given?
          yield results
        end
        results
      end

      # table('ifEntry').  You must pass the direct parent entry.  Calls columns with all
      # columns in +table_name+
      def table(table_name, &blk)
        column_names = MIB::Node.get_node(table_name).children.collect {|c| c.oid }
        results = columns(column_names)
        if block_given?
          yield results
        end
        results
      end

      # Send a PDU
      # +pdu+  The Net::SNMP::PDU object to send.  Usually created by Session.get, Session.getnext, etc.
      # +callback+ An optional callback.  It should take two parameters, status and response_pdu.
      # If no +callback+ is given, the call will block until the response is available and will return
      # the response pdu.  If an error occurs, a Net::SNMP::Error will be thrown.
      # If +callback+ is passed, the PDU will be sent and +send_pdu+ will return immediately.  You must
      # then call Session.select to invoke the callback.  This is usually done in some sort of event loop.
      # See Net::SNMP::Dispatcher.
      #
      # If you're running inside eventmachine and have fibers (ruby 1.9, jruby, etc), sychronous calls will
      # actually run asynchronously behind the scenes.  Just run Net::SNMP::Dispatcher.fiber_loop in your
      # reactor.
      #
      #   pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_GET)
      #   pdu.add_varbind(:oid => 'sysDescr.0')
      #   session.send_pdu(pdu) do |status, pdu|
      #     if status == :success
      #       pdu.print
      #     elsif status == :timeout
      #       puts "Timed Out"
      #     else
      #       puts "A problem occurred"
      #     end
      #   end
      #   session.select(false)  #block until data is ready.  Callback will be called.
      #   begin
      #     result = session.send_pdu(pdu)
      #     puts result.inspect
      #   rescue Net::SNMP::Error => e
      #     puts e.message
      #   end
      def send_pdu(pdu, options = {}, &callback)
        if options[:blocking]
          return send_pdu_blocking(pdu)
        end

        debug "Sending: " do
          pdu.print
        end

        if block_given?
          debug "Setting callback for reqid #{pdu.reqid}"
          @requests[pdu.reqid] = callback
          debug "Calling snmp_sess_async_send"
          if Wrapper.snmp_sess_async_send(@struct, pdu.pointer, sess_callback, nil) == 0
            error("snmp_get async failed")
          end
          nil
        else
          if defined?(EM) && EM.reactor_running? && defined?(Fiber)
            f = Fiber.current
            send_pdu pdu do | op, response_pdu |
              f.resume([op, response_pdu])
            end
            op, result = Fiber.yield
            case op
              when :timeout
                raise TimeoutError.new, "timeout"
              when :send_failed
                error "send failed"
              when :success
                result
              when :connect, :disconnect
                nil   #does this ever happen?
              else
                error "unknown operation #{op}"
            end
          else
            send_pdu_blocking(pdu)
          end
        end

        # if block_given?
        #   debug "Setting callback for reqid #{pdu.reqid}"
        #   @requests[pdu.reqid] = callback
        #   debug "Calling snmp_sess_async_send"
        #   if Wrapper.snmp_sess_async_send(@struct, pdu.pointer, sess_callback, nil) == 0
        #     error("snmp_get async failed")
        #   end
        #   nil
        # elsif defined?(EM) && EM.reactor_running? && defined?(Fiber)
        #   f = Fiber.current
        #   send_pdu pdu do | op, response_pdu |
        #     f.resume([op, response_pdu])
        #   end
        #   op, result = Fiber.yield
        #   case op
        #     when :timeout
        #       raise TimeoutError.new, "timeout"
        #     when :send_failed
        #       error "send failed"
        #     when :success
        #       result
        #     when :connect, :disconnect
        #       nil   #does this ever happen?
        #     else
        #       error "unknown operation #{op}"
        #   end
        # else
        #   send_pdu_blocking(pdu)
        # end
      end

      def send_pdu_blocking(pdu)
        response_ptr = FFI::MemoryPointer.new(:pointer)
        if [Constants::SNMP_MSG_TRAP, Constants::SNMP_MSG_TRAP2, Constants::SNMP_MSG_RESPONSE].include?(pdu.command)
          # Since we don't expect a response, the native net-snmp lib is going to free this
          # pdu for us. Polite, though this may be, it causes intermittent segfaults when freeing
          # memory malloc'ed by ruby. So, clone the pdu into a new memory buffer,
          # and pass that along. The clone is then freed by the native lib. The sent
          # pdu must be freed by the caller.
          clone = Wrapper.snmp_clone_pdu(pdu.struct)
          status = Wrapper.snmp_sess_send(@struct, clone)
          if status == 0
            error("snmp_sess_send")
          end
          :success
        else
          status = Wrapper.snmp_sess_synch_response(@struct, pdu.pointer, response_ptr)
          unless status == Constants::STAT_SUCCESS
            error("snmp_sess_synch_response", :status => status)
          end
          PDU.new(response_ptr.read_pointer)
        end
      end

      def errno
        get_error
        @errno
      end

      # The SNMP Session error code
      def snmp_err
        get_error
        @snmp_err
      end

      # The SNMP Session error message
      def error_message
        get_error
        @snmp_msg
      end

      def print_errors
        puts "errno: #{errno}, snmp_err: #{@snmp_err}, message: #{@snmp_msg}"
      end

      private

      def sess_callback
        @sess_callback ||= FFI::Function.new(:int, [:int, :pointer, :int, :pointer, :pointer]) do |operation, session, reqid, pdu_ptr, magic|
          debug "in sess_callback #{operation.inspect} #{session.inspect}"
          op = case operation
            when Constants::NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE
              :success
            when Constants::NETSNMP_CALLBACK_OP_TIMED_OUT
              :timeout
            when Constants::NETSNMP_CALLBACK_OP_SEND_FAILED
              :send_failed
            when Constants::NETSNMP_CALLBACK_OP_CONNECT
              :connect
            when Constants::NETSNMP_CALLBACK_OP_DISCONNECT
              :disconnect
            else
              error "Invalid PDU Operation"
          end

          if @requests[reqid]
            pdu = PDU.new(pdu_ptr)
            debug "Received:" do
              pdu.print
            end
            callback_return = @requests[reqid].call(op, pdu)
            @requests.delete(reqid)
            callback_return == false ? 0 : 1 #if callback returns false (failure), pass it on.  otherwise return 1 (success)
          else
            0 # Do what here?  Can this happen?  Maybe request timed out and was deleted?
          end
        end
      end

      def get_error
        errno_ptr = FFI::MemoryPointer.new(:int)
        snmp_err_ptr = FFI::MemoryPointer.new(:int)
        msg_ptr = FFI::MemoryPointer.new(:pointer)
        Wrapper.snmp_sess_error(@struct.pointer, errno_ptr, snmp_err_ptr, msg_ptr)
        @errno = errno_ptr.null? ? nil : errno_ptr.read_int
        @snmp_err = snmp_err_ptr.null? ? nil : snmp_err_ptr.read_int
        @snmp_msg = (msg_ptr.null? || msg_ptr.read_pointer.null?) ? nil : msg_ptr.read_pointer.read_string
      end

    end
  end
end
