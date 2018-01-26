module Net
  module SNMP
    module Wrapper
      extend NiceFFI::Library
      ffi_lib %w[libnetsnmp netsnmp]
      typedef :u_long, :oid

      class Counter64 < NiceFFI::Struct
        layout(
          :high, :u_long,
          :low, :u_long
        )
      end

      class TimeVal < NiceFFI::Struct
        layout(:tv_sec, :long, :tv_usec, :long)
      end

      class NetsnmpVardata < FFI::Union
        layout(
          :integer, :pointer,
          :string, :pointer,
          :objid, :pointer,
          :bitstring, :pointer,
          :counter64, :pointer,
          :float, :pointer,
          :double, :pointer
        )
      end

      def self.print_varbind(v)
        puts '---------------------VARBIND------------------------'
        puts %(
      name_length #{v.name_length}
      name #{v.name.read_array_of_long(v.name_length).join('.')}
      type = #{v.type}
             )
      end

      class VariableList < NiceFFI::Struct
        layout(
          :next_variable, VariableList.typed_pointer,
          :name, :pointer,
          :name_length, :size_t,
          :type, :u_char,
          :val, NetsnmpVardata,
          :val_len, :size_t,
          :name_loc, [:oid, Net::SNMP::MAX_OID_LEN],
          :buf, [:u_char, 40],
          :data, :pointer,
          :dataFreeHook, callback([:pointer], :void),
          :index, :int
        )
      end

      def self.print_pdu(p)
        puts '--------------PDU---------------'
        puts %(
      version = #{p.version}
      command = #{p.command}
      errstat = #{p.errstat}
      errindex = #{p.errindex}
             )
        v = p.variables.pointer
        puts '-----VARIABLES------'
        until v.null?
          var = VariableList.new v
          print_varbind(var)
          v = var.next_variable
        end
      end

      class UsmUser < NiceFFI::Struct
        # 00061         u_char         *engineID;
        # 00062         size_t          engineIDLen;
        # 00063         char           *name;
        # 00064         char           *secName;
        # 00065         oid            *cloneFrom;
        # 00066         size_t          cloneFromLen;
        # 00067         oid            *authProtocol;
        # 00068         size_t          authProtocolLen;
        # 00069         u_char         *authKey;
        # 00070         size_t          authKeyLen;
        # 00071         oid            *privProtocol;
        # 00072         size_t          privProtocolLen;
        # 00073         u_char         *privKey;
        # 00074         size_t          privKeyLen;
        # 00075         u_char         *userPublicString;
        # 00076         size_t          userPublicStringLen;
        # 00077         int             userStatus;
        # 00078         int             userStorageType;
        # 00079        /* these are actually DH * pointers but only if openssl is avail. */
        # 00080         void           *usmDHUserAuthKeyChange;
        # 00081         void           *usmDHUserPrivKeyChange;
        # 00082         struct usmUser *next;
        # 00083         struct usmUser *prev;

        layout(
          :engineID, :uchar,
          :engineIDLen, :size_t,
          :name, :char,
          :secName, :char,
          :cloneFrom, :pointer,
          :cloneFromLen, :size_t,
          :authProtocol, :pointer,
          :authProtocolLen, :size_t,
          :authKey, :u_char,
          :authKeyLen, :size_t,
          :privProtocol, :pointer,
          :privProtocolLen, :size_t,
          :privKey, :u_char,
          :privKeyLen, :size_t,
          :userPublicString, :u_char,
          :userPublicStringLen, :size_t,
          :userStatus, :int,
          :userStorageType, :int
        )
      end

      class SnmpPdu < NiceFFI::Struct
        layout(
          :version, :long,
          :command, :int,
          :reqid, :long,
          :msgid, :long,
          :transid, :long,
          :sessid, :long,
          :errstat, :long,
          :errindex, :long,
          :time, :u_long,
          :flags, :u_long,
          :securityModel, :int,
          :securityLevel, :int,
          :msgParseModel, :int,
          :transport_data, :pointer,
          :transport_data_length, :int,
          :tDomain, :pointer,
          :tDomainLen, :size_t,
          :variables, VariableList.typed_pointer,
          :community, :pointer,
          :community_len, :size_t,
          :enterprise, :pointer,
          :enterprise_length, :size_t,
          :trap_type, :long,
          :specific_type, :long,
          :agent_addr, [:uchar, 4],
          :contextEngineID, :pointer,
          :contextEngineIDLen, :size_t,
          :contextName, :pointer,
          :contextNameLen, :size_t,
          :securityEngineID, :pointer,
          :securityEngineIDLen, :size_t,
          :securityName, :pointer,
          :securityNameLen, :size_t,
          :priority, :int,
          :range_subid, :int,
          :securityStateRef, :pointer
        )
      end

      callback(:snmp_callback, %i[int pointer int pointer pointer], :int)
      callback(:netsnmp_callback, %i[int pointer int pointer pointer], :int)

      def self.print_session(s)
        puts '-------------------SESSION---------------------'
        puts %(
      peername = #{s.peername.read_string}
      community = #{s.community.read_string(s.community_len)}
      s_errno = #{s.s_errno}
      s_snmp_errno = #{s.s_snmp_errno}
      securityAuthKey = #{s.securityAuthKey.to_ptr.read_string}
             )
      end

      class SnmpSession < NiceFFI::Struct
        layout(
          :version, :long,
          :retries, :int,
          :timeout, :long,
          :flags, :u_long,
          :subsession, :pointer,
          :next, :pointer,
          :peername, :pointer,
          :remote_port, :u_short,
          :localname, :pointer,
          :local_port, :u_short,
          :authenticator, callback(%i[pointer pointer pointer uint], :pointer),
          :callback, :netsnmp_callback,
          :callback_magic, :pointer,
          :s_errno, :int,
          :s_snmp_errno, :int,
          :sessid, :long,
          :community, :pointer,
          :community_len, :size_t,
          :rcvMsgMaxSize, :size_t,
          :sndMsgMaxSize, :size_t,
          :isAuthoritative, :u_char,
          :contextEngineID, :pointer,
          :contextEngineIDLen, :size_t,
          :engineBoots, :u_int,
          :engineTime, :u_int,
          :contextName, :pointer,
          :contextNameLen, :size_t,
          :securityEngineID, :pointer,
          :securityEngineIDLen, :size_t,
          :securityName, :pointer,
          :securityNameLen, :size_t,
          :securityAuthProto, :pointer,
          :securityAuthProtoLen, :size_t,
          :securityAuthKey, [:u_char, 32],
          :securityAuthKeyLen, :size_t,
          :securityAuthLocalKey, :pointer,
          :securityAuthLocalKeyLen, :size_t,
          :securityPrivProto, :pointer,
          :securityPrivProtoLen, :size_t,
          :securityPrivKey, [:u_char, 32],
          :securityPrivKeyLen, :size_t,
          :securityPrivLocalKey, :pointer,
          :securityPrivLocalKeyLen, :size_t,
          :securityModel, :int,
          :securityLevel, :int,
          :paramName, :pointer,
          :securityInfo, :pointer,
          :myvoid, :pointer
        )
      end

      class EnumList < NiceFFI::Struct
        layout(
          :next, EnumList.typed_pointer,
          :value, :int,
          :label, :pointer
        )
      end

      class IndexList < NiceFFI::Struct
        layout(
          :next, :pointer,
          :ilabel, :pointer,
          :isimplied, :char
        )
      end

      class ModuleImport < NiceFFI::Struct
        layout(
          :label, :pointer, # The descriptor being imported (pointer to string)
          :modid, :int # The module id
        )
      end

      class Module < NiceFFI::Struct
        layout(
          :name, :pointer, # The module's name (pointer to string)
          :file, :pointer, # The file containing the module (pointer to string)
          :imports, ModuleImport.typed_pointer, # List of descriptors being imported
          :no_imports, :int, # The length of the imports array
          :modid, :int, # The index number of this module
          :next, Module.typed_pointer # Linked list pointer
        )
      end

      class Tree < NiceFFI::Struct
        layout(
          :child_list, Tree.typed_pointer,
          :next_peer, Tree.typed_pointer,
          :next, Tree.typed_pointer,
          :parent, :pointer,
          :label, :string,
          :subid, :u_long,
          :modid, :int,
          :number_modules, :int, # Length of module_list array
          :module_list, :pointer, # Array of modids (pointer to int)
          :tc_index, :int,
          :type, :int,
          :access, :int,
          :status, :int,
          :enums, EnumList.typed_pointer,
          :ranges, :pointer,
          :indexes, IndexList.typed_pointer,
          :augments, :pointer,
          :varbinds, :pointer,
          :hint, :pointer,
          :units, :pointer,
          :printomat, callback(%i[pointer pointer pointer int pointer pointer pointer pointer], :int),
          :printer, callback(%i[pointer pointer pointer pointer pointer], :void),
          :description, :pointer,
          :reference, :pointer,
          :reported, :int,
          :defaultValue, :pointer
        )
      end

      # Some of these functions/variables are not available on windows.
      # (At least with my current setup.) Simple SNMP manager example
      # seems to work fine without them, so just log and ignore for now.
      class << self
        include Net::SNMP::Debug
        alias af attach_function

        def attach_function(*args)
          af(*args)
        rescue Exception => ex
          debug ex.message
        end
      end

      attach_function :snmp_clone_pdu, [:pointer], :pointer
      attach_function :snmp_open, [:pointer], SnmpSession.typed_pointer
      attach_function :snmp_errstring, [:int], :string
      attach_function :snmp_close, [:pointer], :int
      attach_function :snmp_close_sessions, [], :int
      attach_function :snmp_send, %i[pointer pointer], :int
      attach_function :snmp_async_send, %i[pointer pointer netsnmp_callback pointer], :int
      attach_function :snmp_read, [:pointer], :void
      attach_function :snmp_free_pdu, [:pointer], :void
      attach_function :snmp_free_var, [:pointer], :void
      attach_function :snmp_free_varbind, [:pointer], :void
      attach_function :snmp_select_info, %i[pointer pointer pointer pointer], :int
      attach_function :snmp_timeout, [], :void

      attach_function :snmp_get_next_msgid, [], :long
      attach_function :snmp_get_next_reqid, [], :long
      attach_function :snmp_get_next_sessid, [], :long
      attach_function :snmp_get_next_transid, [], :long
      attach_function :snmp_oid_compare, %i[pointer uint pointer uint], :int
      attach_function :snmp_oid_ncompare, %i[pointer uint pointer uint uint], :int
      attach_function :snmp_oidtree_compare, %i[pointer uint pointer uint], :int
      attach_function :snmp_oidsubtree_compare, %i[pointer uint pointer uint], :int
      attach_function :netsnmp_oid_compare_ll, %i[pointer uint pointer uint pointer], :int
      attach_function :netsnmp_oid_equals, %i[pointer uint pointer uint], :int
      attach_function :netsnmp_oid_tree_equals, %i[pointer size_t pointer size_t], :int
      attach_function :netsnmp_oid_is_subtree, %i[pointer uint pointer uint], :int
      attach_function :netsnmp_oid_find_prefix, %i[pointer uint pointer uint], :int
      attach_function :netsnmp_transport_open_client, %i[string pointer], :pointer
      attach_function :init_snmp, [:string], :void
      attach_function :snmp_pdu_build, %i[pointer pointer pointer], :pointer
      attach_function :snmpv3_parse, %i[pointer pointer pointer pointer pointer], :int
      attach_function :snmpv3_packet_build, %i[pointer pointer pointer pointer pointer uint], :int
      attach_function :snmpv3_packet_rbuild, %i[pointer pointer pointer pointer pointer size_t], :int
      attach_function :snmpv3_make_report, %i[pointer int], :int
      attach_function :snmpv3_get_report_type, [:pointer], :int
      attach_function :snmp_pdu_parse, %i[pointer pointer pointer], :int
      attach_function :snmpv3_scopedPDU_parse, %i[pointer pointer pointer], :pointer
      attach_function :snmp_store, [:string], :void
      attach_function :snmp_shutdown, [:string], :void
      attach_function :snmp_pdu_add_variable, %i[pointer pointer uint u_char pointer size_t], :pointer
      attach_function :snmp_varlist_add_variable, %i[pointer pointer uint u_char pointer uint], :pointer
      attach_function :snmp_add_var, %i[pointer pointer uint char string], :int
      attach_function :snmp_duplicate_objid, %i[pointer uint], :pointer
      attach_function :snmp_increment_statistic, [:int], :u_int
      attach_function :snmp_increment_statistic_by, %i[int int], :u_int
      attach_function :snmp_get_statistic, [:int], :u_int
      attach_function :snmp_init_statistics, [], :void
      attach_function :create_user_from_session, [:pointer], :int
      attach_function :snmp_open_ex, [:pointer, callback(%i[pointer pointer pointer int], :int), callback(%i[pointer pointer pointer uint], :int), callback(%i[pointer pointer int], :int), callback(%i[pointer pointer pointer pointer], :int), callback(%i[pointer pointer pointer pointer pointer], :int), callback(%i[pointer uint], :int)], :pointer
      attach_function :snmp_set_do_debugging, [:int], :void
      attach_function :snmp_get_do_debugging, [], :int
      attach_function :snmp_error, %i[pointer pointer pointer pointer], :void
      attach_function :snmp_sess_init, [:pointer], :void
      attach_function :snmp_sess_open, [:pointer], SnmpSession.typed_pointer
      attach_function :snmp_sess_pointer, [:pointer], :pointer
      attach_function :snmp_sess_session, [:pointer], SnmpSession.typed_pointer
      attach_function :snmp_sess_transport, [:pointer], :pointer
      attach_function :snmp_sess_transport_set, %i[pointer pointer], :void
      attach_function :snmp_sess_add_ex, [:pointer, :pointer, callback(%i[pointer pointer pointer int], :int), callback(%i[pointer pointer pointer uint], :int), callback(%i[pointer pointer int], :int), callback(%i[pointer pointer pointer pointer], :int), callback(%i[pointer pointer pointer pointer pointer], :int), callback(%i[pointer uint], :int), callback(%i[pointer pointer uint], :pointer)], :pointer
      attach_function :snmp_sess_add, [:pointer, :pointer, callback(%i[pointer pointer pointer int], :int), callback(%i[pointer pointer int], :int)], :pointer
      attach_function :snmp_add, [:pointer, :pointer, callback(%i[pointer pointer pointer int], :int), callback(%i[pointer pointer int], :int)], :pointer
      attach_function :snmp_add_full, [:pointer, :pointer, callback(%i[pointer pointer pointer int], :int), callback(%i[pointer pointer pointer uint], :int), callback(%i[pointer pointer int], :int), callback(%i[pointer pointer pointer pointer], :int), callback(%i[pointer pointer pointer pointer pointer], :int), callback(%i[pointer uint], :int), callback(%i[pointer pointer uint], :pointer)], :pointer
      attach_function :snmp_sess_send, %i[pointer pointer], :int
      attach_function :snmp_sess_async_send, %i[pointer pointer snmp_callback pointer], :int
      attach_function :snmp_sess_select_info, %i[pointer pointer pointer pointer pointer], :int
      attach_function :snmp_sess_read, %i[pointer pointer], :int
      attach_function :snmp_sess_timeout, [:pointer], :void
      attach_function :snmp_sess_close, [:pointer], :int
      attach_function :snmp_sess_error, %i[pointer pointer pointer pointer], :void
      attach_function :netsnmp_sess_log_error, %i[int string pointer], :void
      attach_function :snmp_sess_perror, %i[string pointer], :void
      attach_function :snmp_pdu_type, [:int], :string

      attach_function :asn_check_packet, %i[pointer uint], :int
      attach_function :asn_parse_int, %i[pointer pointer pointer pointer uint], :pointer
      attach_function :asn_build_int, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_unsigned_int, %i[pointer pointer pointer pointer uint], :pointer
      attach_function :asn_build_unsigned_int, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_string, %i[pointer pointer pointer pointer pointer], :pointer
      attach_function :asn_build_string, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_header, %i[pointer pointer pointer], :pointer
      attach_function :asn_parse_sequence, %i[pointer pointer pointer u_char string], :pointer
      attach_function :asn_build_header, %i[pointer pointer u_char uint], :pointer
      attach_function :asn_build_sequence, %i[pointer pointer u_char uint], :pointer
      attach_function :asn_parse_length, %i[pointer pointer], :pointer
      attach_function :asn_build_length, %i[pointer pointer uint], :pointer
      attach_function :asn_parse_objid, %i[pointer pointer pointer pointer pointer], :pointer
      attach_function :asn_build_objid, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_null, %i[pointer pointer pointer], :pointer
      attach_function :asn_build_null, %i[pointer pointer u_char], :pointer
      attach_function :asn_parse_bitstring, %i[pointer pointer pointer pointer pointer], :pointer
      attach_function :asn_build_bitstring, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_unsigned_int64, %i[pointer pointer pointer pointer uint], :pointer
      attach_function :asn_build_unsigned_int64, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_signed_int64, %i[pointer pointer pointer pointer uint], :pointer
      attach_function :asn_build_signed_int64, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_build_float, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_float, %i[pointer pointer pointer pointer uint], :pointer
      attach_function :asn_build_double, %i[pointer pointer u_char pointer uint], :pointer
      attach_function :asn_parse_double, %i[pointer pointer pointer pointer uint], :pointer

      attach_function :snmp_pdu_create, [:int], SnmpPdu.typed_pointer
      attach_function :get_node, %i[string pointer pointer], :int
      attach_function :read_objid, %i[string pointer pointer], :int
      attach_function :snmp_add_null_var, %i[pointer pointer size_t], :pointer
      attach_function :snmp_sess_synch_response, %i[pointer pointer pointer], :int
      attach_function :snmp_synch_response, %i[pointer pointer pointer], :int
      attach_function :snmp_parse_oid, %i[string pointer pointer], :pointer
      attach_function :snmp_api_errstring, [:int], :string
      attach_function :snmp_perror, [:string], :void
      attach_function :snmp_set_detail, [:string], :void

      attach_function :generate_Ku, %i[pointer int string int pointer pointer], :int

      # MIB functions
      attach_function :netsnmp_init_mib, [], :void
      attach_function :read_all_mibs, [], :void
      attach_function :add_mibdir, [:string], :int
      attach_function :read_mib, [:string], Tree.typed_pointer
      attach_function :netsnmp_read_module, [:string], Tree.typed_pointer
      attach_function :snmp_set_save_descriptions, [:int], :void

      attach_function :get_tree_head, [], Tree.typed_pointer
      attach_function :get_tree, %i[pointer int pointer], Tree.typed_pointer

      # struct module  *find_module(int modid);
      attach_function :find_module, [:int], Module.typed_pointer

      # USM User functions
      # Needed for: https://stackoverflow.com/questions/18380435/net-snmp-is-not-changing-auth-and-priv-protocol-correctly
      # http://www.net-snmp.org/dev/agent/snmpusm_8h-source.html
      attach_function :clear_user_list, [], :void

      def self.get_fd_set
        FFI::MemoryPointer.new(:pointer, 128)
      end
    end
  end
end

module FFI
  module LibC
    extend FFI::Library
    ffi_lib 'c'

    typedef :pointer, :FILE
    typedef :uint32, :in_addr_t
    typedef :uint16, :in_port_t

    class Timeval < FFI::Struct
      layout :tv_sec, :time_t,
             :tv_usec, :suseconds_t
    end

    # Some of these functions/variables are not available on windows.
    # (At least with my current setup.) Simple SNMP manager example
    # seems to work fine without them, so just log and ignore for now.
    class << self
      include Net::SNMP::Debug
      alias af attach_function

      def attach_function(*args)
        af(*args)
      rescue Exception => ex
        debug ex.message
      end

      alias av attach_variable

      def attach_variable(*args)
        av(*args)
      rescue Exception => ex
        debug ex.message
      end
    end

    # Standard IO functions
    # @blocking = true  # some undocumented voodoo that tells the next attach_function to release the GIL
    attach_function :malloc, [:size_t], :pointer
    attach_function :calloc, %i[size_t size_t], :pointer
    attach_function :memcpy, %i[pointer pointer size_t], :pointer
    attach_function :free, [:pointer], :void
    # attach_variable :errno, :int

    ffi_lib ['Ws2_32.dll'] if ENV['OS'] =~ /windows/i
    attach_function :select, %i[int pointer pointer pointer pointer], :int
  end
end
