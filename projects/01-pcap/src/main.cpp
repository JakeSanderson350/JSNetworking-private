#include <iostream>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <ArpLayer.h>
#include <IcmpLayer.h>

int main() {
    // Open the pcap file
    const std::string pcapFile = "data/The Ultimate PCAP v20251206.pcapng";

    std::cout << "Opening file: " << pcapFile << std::endl << std::flush;

    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFile);

    if (reader == nullptr) {
        std::cerr << "Cannot determine reader for file: " << pcapFile << std::endl;
        return 1;
    }

    if (!reader->open()) {
        std::cerr << "Cannot open file: " << pcapFile << std::endl;
        delete reader;
        return 1;
    }

    std::cout << "Successfully opened: " << pcapFile << std::endl << std::flush;

    // Read and analyze packets
    pcpp::RawPacket rawPacket;

    // Task 1: Basic Packet Statistics
    int packetCount = 0;
    int ipv4Count = 0;
    int ipv6Count = 0;
    int tcpCount = 0;
    int udpCount = 0;
    int arpCount = 0;
    int icmpCount = 0;

    // Task 2: Layer Analysis
    int ethernetCount = 0;
    int multiLayerCount = 0;  // Ethernet + IP + TCP/UDP

    while (reader->getNextPacket(rawPacket)) {
        packetCount++;

        // Parse the raw packet
        pcpp::Packet parsedPacket(&rawPacket);

        // Task 1: Check protocol types
        if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
            ipv4Count++;
        }

        if (parsedPacket.isPacketOfType(pcpp::IPv6)) {
            ipv6Count++;
        }

        if (parsedPacket.isPacketOfType(pcpp::TCP)) {
            tcpCount++;
        }

        if (parsedPacket.isPacketOfType(pcpp::UDP)) {
            udpCount++;
        }

        if (parsedPacket.isPacketOfType(pcpp::ARP)) {
            arpCount++;
        }

        if (parsedPacket.isPacketOfType(pcpp::ICMP)) {
            icmpCount++;
        }

        // Task 2: Layer Analysis
        bool hasEthernet = parsedPacket.isPacketOfType(pcpp::Ethernet);
        bool hasIP = parsedPacket.isPacketOfType(pcpp::IPv4) || parsedPacket.isPacketOfType(pcpp::IPv6);
        bool hasTransport = parsedPacket.isPacketOfType(pcpp::TCP) || parsedPacket.isPacketOfType(pcpp::UDP);

        if (hasEthernet) {
            ethernetCount++;
        }

        // Multi-layer: Ethernet + IP + TCP/UDP
        if (hasEthernet && hasIP && hasTransport) {
            multiLayerCount++;
        }
    }

    // Print Task 1 Summary
    std::cout << "\n=== Task 1: Basic Packet Statistics ===" << std::endl;
    std::cout << "Total packets: " << packetCount << std::endl;
    std::cout << "IPv4 packets:  " << ipv4Count << std::endl;
    std::cout << "IPv6 packets:  " << ipv6Count << std::endl;
    std::cout << "TCP packets:   " << tcpCount << std::endl;
    std::cout << "UDP packets:   " << udpCount << std::endl;
    std::cout << "ARP packets:   " << arpCount << std::endl;
    std::cout << "ICMP packets:  " << icmpCount << std::endl;

    // Print Task 2 Summary
    std::cout << "\n=== Task 2: Layer Analysis ===" << std::endl;
    std::cout << "Ethernet frames:        " << ethernetCount << std::endl;
    std::cout << "\nLayer 3 (Network) distribution:" << std::endl;
    std::cout << "  IPv4:  " << ipv4Count << std::endl;
    std::cout << "  IPv6:  " << ipv6Count << std::endl;
    std::cout << "  ARP:   " << arpCount << std::endl;
    std::cout << "\nLayer 4 (Transport) distribution:" << std::endl;
    std::cout << "  TCP:   " << tcpCount << std::endl;
    std::cout << "  UDP:   " << udpCount << std::endl;
    std::cout << "  ICMP:  " << icmpCount << std::endl;
    std::cout << "\nMulti-layer packets (Eth+IP+TCP/UDP): " << multiLayerCount << std::endl;

    // Close the file
    reader->close();
    delete reader;

    std::cout << "\nPcapPlusPlus is working correctly!" << std::endl;

    return 0;
}
