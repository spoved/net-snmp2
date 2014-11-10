module Net
  module SNMP
    class TrapSession < Session
      # == Represents a session for sending SNMP traps

      # +options+
      # * :peername The address where the trap will be sent
      # * :port     The port where the trap will be sent (default = 162)
      def initialize(options = {})
        # Unless the port was supplied in the peername...
        unless options[:peername][":"]
          # ...default to standard trap port
          options[:port] ||= 162
        end

        super(options)
      end

      # Send an SNMPv1 trap
      #
      # Options
      #
      # - enterprise: The Oid of the enterprise
      # - trap_type:  The generic trap type.
      # - specific_type: The specific trap type
      # - uptime: The uptime for this agent
      def trap(options = {})
        pdu = PDU.new(Constants::SNMP_MSG_TRAP)
        options[:enterprise] ||= '1.3.6.1.4.1.3.1.1'  # Default =
        pdu.enterprise = OID.new(options[:enterprise].to_s)
        pdu.trap_type = options[:trap_type].to_i || 1  # need to check all these defaults
        pdu.specific_type = options[:specific_type].to_i || 0
        pdu.time = options[:uptime].to_i || 1
        pdu.agent_addr = options[:agent_addr] || '127.0.0.1'
        if options[:varbinds]
          options[:varbinds].each do |vb|
            pdu.add_varbind(vb)
          end
        end
        result = send_pdu(pdu)
        pdu.free
        result
      end

      # Send an SNMPv2 trap
      # +options
      # * :oid The Oid of the trap
      # * :varbinds A list of Varbind objects to send with the trap
      def trap_v2(options = {})
        if options[:oid].kind_of?(String)
          options[:oid] = Net::SNMP::OID.new(options[:oid])
        end
        pdu = PDU.new(Constants::SNMP_MSG_TRAP2)
        build_trap_pdu(pdu, options)
        result = send_pdu(pdu)
        pdu.free
        result
      end

      # Send an SNMPv2 inform.  Can accept a callback to execute on confirmation of the inform
      # +options
      # * :oid The OID of the inform
      # * :varbinds A list of Varbind objects to send with the inform
      def inform(options = {}, &callback)
        if options[:oid].kind_of?(String)
          options[:oid] = Net::SNMP::OID.new(options[:oid])
        end
        pdu = PDU.new(Constants::SNMP_MSG_INFORM)
        build_trap_pdu(pdu, options)
        result = send_pdu(pdu, &callback)
        pdu.free
      end

      private
      def build_trap_pdu(pdu, options = {})
        options[:uptime] ||= 1
        pdu.add_varbind(:oid => OID.new('sysUpTime.0'), :type => Constants::ASN_TIMETICKS, :value => options[:uptime].to_i)
        pdu.add_varbind(:oid => OID.new('snmpTrapOID.0'), :type => Constants::ASN_OBJECT_ID, :value => options[:oid])
        if options[:varbinds]
          options[:varbinds].each do |vb|
            pdu.add_varbind(vb)
          end
        end
      end
    end
  end
end
