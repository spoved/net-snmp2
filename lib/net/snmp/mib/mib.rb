module Net
  module SNMP
    module MIB
      # Configures the MIB directory search path (using add_mibdir ), sets up the internal
      # MIB framework, and then loads the appropriate MIB modules (using netsnmp_read_module
      # and  read_mib). It should be called before any other routine that manipulates
      # or accesses the MIB tree (but after any additional add_mibdir calls).
      def self.init
        Wrapper.netsnmp_init_mib
      end

      # Read in all the MIB modules found on the MIB directory search list
      def self.read_all_mibs
        Wrapper.read_all_mibs
      end

      # Get an OID object representing the MIB node containing `oid`
      # - `oid` argument may be a numerical oid, or the MIB name
      def self.get_node(oid)
        Node.get_node(oid)
      end

      # Get an OID object representing the MIB node containing `oid`
      # - `oid` argument may be a numerical oid, or the MIB name
      def self.[](oid)
        Node.get_node(oid)
      end

      # Translates a numerical oid to it's MIB name, or a name to numerical oid
      def self.translate(oid)
        node = Node.get_node(oid)
        if oid =~ /^[0-9.]*$/
          # Node label + instance indexes from argument
          "#{node.label}#{oid.sub(node.oid.to_s, '')}"
        else
          # Node OID + instance indexes from argument
          # (Regex ensures the module qualifier is also removed, if present)
          "#{node.oid}#{oid.sub(/.*#{node.label.to_s}/, '')}"
        end
      end

      # Add the specified directory to the path of locations which are searched
      # for files containing MIB modules. Note that this does not actually load
      # the MIB modules located in that directory
      def self.add_mibdir(dirname)
        Wrapper.add_mibdir(dirname)
      end

      # Takes the name of a MIB module (which need not be the same as the name
      # of the file that contains the module), locates this within the configured
      # list of MIB directories, and loads the definitions from the module into
      # the active MIB tree. It also loads any MIB modules listed in the IMPORTS
      # clause of this module.
      def self.read_module(name)
        Wrapper.netsnmp_read_module(name)
      end

      # Similar to read_module, but takes the name of the file containing the MIB
      # module. Note that this file need not be located within the MIB directory
      # search list (although any modules listed in the IMPORTS clause do).
      def self.read_mib(filename)
        Wrapper.read_mib(filename)
      end
    end
  end
end
