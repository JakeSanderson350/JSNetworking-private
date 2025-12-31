#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <iostream>
#include <fstream>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <ArpLayer.h>
#include <IcmpLayer.h>

// Structure to hold packet statistics for Task 1
struct BasicStats {
    int totalPackets = 0;
    int ipv4Packets = 0;
    int ipv6Packets = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int arpPackets = 0;
    int icmpPackets = 0;
};

// Structure to hold layer analysis for Task 2
struct LayerStats {
    // Layer 2 (Data Link)
    int ethernetFrames = 0;
    // Layer 3 (Network)
    int layer3_ipv4 = 0;
    int layer3_ipv6 = 0;
    int layer3_arp = 0;
    // Layer 4 (Transport)
    int layer4_tcp = 0;
    int layer4_udp = 0;
    int layer4_icmp = 0;
};

// TODO: Implement this function to count packets by protocol type
// 
// Your task:
//   1. Open the PCAP file and iterate through all packets
//   2. For each packet, check which protocol layers are present
//   3. Increment the appropriate counters in the BasicStats struct
//
// Useful PcapPlusPlus API:
//   - pcpp::IFileReaderDevice::getReader(filename) - creates a file reader
//   - reader->open() / reader->close() - open/close the file
//   - reader->getNextPacket(rawPacket) - reads next packet into rawPacket
//   - pcpp::Packet parsedPacket(&rawPacket) - parses a raw packet
//   - parsedPacket.isPacketOfType(pcpp::IPv4) - checks protocol type
//   - Protocol constants: pcpp::IPv4, pcpp::IPv6, pcpp::TCP, pcpp::UDP, 
//                         pcpp::ARP, pcpp::ICMP, pcpp::Ethernet
BasicStats analyzeBasicStats(const std::string& pcapFile) {
    BasicStats stats;

    // TODO: Implement packet counting logic here
    //
    // Example iteration pattern:
    //   pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFile);
    //   if (reader == nullptr || !reader->open()) return stats;
    //   pcpp::RawPacket rawPacket;
    //   while (reader->getNextPacket(rawPacket)) {
    //       pcpp::Packet parsedPacket(&rawPacket);
    //       // ... check packet types here ...
    //   }
    //   reader->close();
    //   delete reader;
    //
    // Checking packet types (can check multiple per packet):
    //   if (parsedPacket.isPacketOfType(pcpp::IPv4)) { ... }
    //   if (parsedPacket.isPacketOfType(pcpp::TCP)) { ... }
    //
    // Alternative: get layer directly (returns nullptr if not present):
    //   auto* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    //   if (ipv4Layer != nullptr) { ... }
    //
    (void)pcapFile; // Remove this line when implementing

    return stats;
}

// TODO: Implement this function to analyze the OSI layer distribution
//
// Your task:
//   1. Open the PCAP file and iterate through all packets
//   2. Count packets at each layer:
//      - Layer 2: Ethernet frames
//      - Layer 3: IPv4, IPv6, ARP
//      - Layer 4: TCP, UDP, ICMP
//
// Use the same API as analyzeBasicStats()
LayerStats analyzeLayerStats(const std::string& pcapFile) {
    LayerStats stats;

    // TODO: Implement layer analysis logic here
    //
    // Use the same iteration pattern as analyzeBasicStats():
    //   pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFile);
    //   if (reader == nullptr || !reader->open()) return stats;
    //   pcpp::RawPacket rawPacket;
    //   while (reader->getNextPacket(rawPacket)) {
    //       pcpp::Packet parsedPacket(&rawPacket);
    //       // ... check layers here ...
    //   }
    //   reader->close();
    //   delete reader;
    //
    // Layer checks:
    //   Layer 2: parsedPacket.isPacketOfType(pcpp::Ethernet)
    //   Layer 3: parsedPacket.isPacketOfType(pcpp::IPv4)
    //            parsedPacket.isPacketOfType(pcpp::IPv6)
    //            parsedPacket.isPacketOfType(pcpp::ARP)
    //   Layer 4: parsedPacket.isPacketOfType(pcpp::TCP)
    //            parsedPacket.isPacketOfType(pcpp::UDP)
    //            parsedPacket.isPacketOfType(pcpp::ICMP)
    //
    (void)pcapFile; // Remove this line when implementing

    return stats;
}

const std::string PCAP_FILE = "data/The Ultimate PCAP v20251206.pcapng";

TEST_CASE("PCAP file can be opened") {
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(PCAP_FILE);
    REQUIRE_MESSAGE(reader != nullptr, "Cannot determine reader for file: " << PCAP_FILE);
    REQUIRE_MESSAGE(reader->open(), "Cannot open file: " << PCAP_FILE << ". Make sure the PCAP file is extracted.");
    reader->close();
    delete reader;
}

TEST_CASE("Task 1: Basic Packet Statistics") {
    BasicStats stats = analyzeBasicStats(PCAP_FILE);

    MESSAGE("Task 1 Results:");
    MESSAGE("  Total packets: " << stats.totalPackets);
    MESSAGE("  IPv4 packets:  " << stats.ipv4Packets);
    MESSAGE("  IPv6 packets:  " << stats.ipv6Packets);
    MESSAGE("  TCP packets:   " << stats.tcpPackets);
    MESSAGE("  UDP packets:   " << stats.udpPackets);
    MESSAGE("  ARP packets:   " << stats.arpPackets);
    MESSAGE("  ICMP packets:  " << stats.icmpPackets);

    SUBCASE("Total packet count") {
        CHECK_MESSAGE(stats.totalPackets == 48640,
            "Expected 48640 total packets, got " << stats.totalPackets);
    }

    SUBCASE("IPv4 packet count") {
        CHECK_MESSAGE(stats.ipv4Packets == 4065,
            "Expected 4065 IPv4 packets, got " << stats.ipv4Packets);
    }

    SUBCASE("IPv6 packet count") {
        CHECK_MESSAGE(stats.ipv6Packets == 1283,
            "Expected 1283 IPv6 packets, got " << stats.ipv6Packets);
    }

    SUBCASE("TCP packet count") {
        CHECK_MESSAGE(stats.tcpPackets == 1726,
            "Expected 1726 TCP packets, got " << stats.tcpPackets);
    }

    SUBCASE("UDP packet count") {
        CHECK_MESSAGE(stats.udpPackets == 2660,
            "Expected 2660 UDP packets, got " << stats.udpPackets);
    }

    SUBCASE("ARP packet count") {
        CHECK_MESSAGE(stats.arpPackets == 56,
            "Expected 56 ARP packets, got " << stats.arpPackets);
    }

    SUBCASE("ICMP packet count") {
        CHECK_MESSAGE(stats.icmpPackets == 45,
            "Expected 45 ICMP packets, got " << stats.icmpPackets);
    }
}

TEST_CASE("Task 2: Layer Analysis") {
    LayerStats stats = analyzeLayerStats(PCAP_FILE);

    MESSAGE("Task 2 Results:");
    MESSAGE("  Layer 2 - Ethernet: " << stats.ethernetFrames);
    MESSAGE("  Layer 3 - IPv4: " << stats.layer3_ipv4);
    MESSAGE("  Layer 3 - IPv6: " << stats.layer3_ipv6);
    MESSAGE("  Layer 3 - ARP:  " << stats.layer3_arp);
    MESSAGE("  Layer 4 - TCP:  " << stats.layer4_tcp);
    MESSAGE("  Layer 4 - UDP:  " << stats.layer4_udp);
    MESSAGE("  Layer 4 - ICMP: " << stats.layer4_icmp);

    SUBCASE("Layer 2: Ethernet frame count") {
        CHECK_MESSAGE(stats.ethernetFrames == 5264,
            "Expected 5264 Ethernet frames, got " << stats.ethernetFrames);
    }

    SUBCASE("Layer 3: IPv4 packet count") {
        CHECK_MESSAGE(stats.layer3_ipv4 == 4065,
            "Expected 4065 IPv4 packets, got " << stats.layer3_ipv4);
    }

    SUBCASE("Layer 3: IPv6 packet count") {
        CHECK_MESSAGE(stats.layer3_ipv6 == 1283,
            "Expected 1283 IPv6 packets, got " << stats.layer3_ipv6);
    }

    SUBCASE("Layer 3: ARP packet count") {
        CHECK_MESSAGE(stats.layer3_arp == 56,
            "Expected 56 ARP packets, got " << stats.layer3_arp);
    }

    SUBCASE("Layer 4: TCP segment count") {
        CHECK_MESSAGE(stats.layer4_tcp == 1726,
            "Expected 1726 TCP segments, got " << stats.layer4_tcp);
    }

    SUBCASE("Layer 4: UDP datagram count") {
        CHECK_MESSAGE(stats.layer4_udp == 2660,
            "Expected 2660 UDP datagrams, got " << stats.layer4_udp);
    }

    SUBCASE("Layer 4: ICMP packet count") {
        CHECK_MESSAGE(stats.layer4_icmp == 45,
            "Expected 45 ICMP packets, got " << stats.layer4_icmp);
    }
}

// Helper function to check if a file exists
bool fileExists(const std::string& filename) {
    std::ifstream f(filename);
    return f.good();
}

TEST_CASE("Screenshots: Required PNG files exist") {
    SUBCASE("repo_name.png exists") {
        CHECK_MESSAGE(fileExists("repo_name.png"),
            "Missing screenshot: repo_name.png - Take a screenshot of your private repository's main page");
    }

    SUBCASE("actions_enabled.png exists") {
        CHECK_MESSAGE(fileExists("actions_enabled.png"),
            "Missing screenshot: actions_enabled.png - Take a screenshot of the Actions tab showing CI is enabled");
    }

    SUBCASE("collaborators.png exists") {
        CHECK_MESSAGE(fileExists("collaborators.png"),
            "Missing screenshot: collaborators.png - Take a screenshot showing instructor added as collaborator");
    }

    SUBCASE("ai_disabled.png exists") {
        CHECK_MESSAGE(fileExists("ai_disabled.png"),
            "Missing screenshot: ai_disabled.png - Take a screenshot showing AI code completion is disabled");
    }
}