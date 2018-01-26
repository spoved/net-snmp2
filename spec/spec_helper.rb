$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'net-snmp2'
require 'rspec'

# Trap tests fail randomly due to race conditions,
# setting thread_safe should fix this
# Net::SNMP::Debug.logger = Logger.new(STDOUT)
# Net::SNMP::Debug.logger.level = Logger::INFO
Net::SNMP.thread_safe = true
Net::SNMP.init

# Must require after calling `SNMP.init`
require 'test_mib'
