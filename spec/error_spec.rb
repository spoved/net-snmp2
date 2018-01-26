require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require 'eventmachine'

describe 'snmp errors' do
  it 'should rescue a timeout error' do
    Net::SNMP::Session.open(peername: 'www.yahoo.com') do |sess|
      begin
        sess.get('sysDescr.0')
      rescue Net::SNMP::Error => e
        e.print
        expect(e.status).to eql(Net::SNMP::Constants::STAT_TIMEOUT)
      end
    end
  end

  it 'should rescue timeout error in a fiber' do
    got_error = false
    EM.run do
      Fiber.new do
        Net::SNMP::Dispatcher.fiber_loop
        Net::SNMP::Session.open(peername: 'www.yahoo.com') do |sess|
          begin
            sess.get('sysDescr.0')
          rescue Net::SNMP::TimeoutError => e
            got_error = true
          end
        end
        EM.stop
      end.resume(nil)
    end
    expect(got_error).to eq(true)
  end
end
