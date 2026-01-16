#include <iostream>
#include <PcapReader.h>

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

    // ========================================
    // EDUCATIONAL INSIGHTS FOR PCAP ANALYSIS
    // ========================================
    //
    // You now have a reader that can iterate through the PCAP file.
    // This is where YOUR implementation goes in the test functions!
    //
    // Key Concepts to Understand:
    // 
    // 1. PACKET ITERATION:
    //    - Use getNextPacket(rawPacket) to read packets sequentially
    //    - Each call returns one packet and advances the pointer
    //    - When no more packets exist, the function returns false
    //
    // 2. PACKET PARSING:
    //    - pcpp::Packet wraps pcpp::RawPacket for easy layer access
    //    - isPacketOfType() checks for protocol presence (non-destructive)
    //    - getLayerOfType<T>() retrieves specific layer objects
    //
    // 3. PROTOCOL CHECKING PATTERNS:
    //    Pattern A (boolean check):
    //      if (packet.isPacketOfType(pcpp::IPv4)) { count++; }
    //
    //    Pattern B (layer retrieval):
    //      auto* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    //      if (ipv4Layer != nullptr) { /* process layer */ }
    //
    // 4. OSI MODEL CONTEXT:
    //    - Layer 2 (Data Link): Ethernet (hardware addressing)
    //    - Layer 3 (Network):   IPv4, IPv6, ARP (logical routing)
    //    - Layer 4 (Transport): TCP, UDP, ICMP (end-to-end delivery)
    //    
    //    Note: A single packet can contain multiple protocols!
    //    Example: Ethernet -> IPv4 -> TCP -> Application Data
    //
    // 5. COUNTING STRATEGIES:
    //    - Total packets: Count every packet read from file
    //    - Protocol packets: Check which layers are present per packet
    //    - Each check is independent (a TCP packet is ALSO an IPv4 packet)
    //
    // 6. PRACTICAL IMPLEMENTATION STEPS:
    //    a) Create counter variables for each protocol type
    //    b) Loop through packets with getNextPacket()
    //    c) Parse each raw packet into a Packet object
    //    d) Use isPacketOfType() to check for protocol presence
    //    e) Increment corresponding counters
    //    f) Store results in the struct and return
    //
    // DEBUGGING TIPS:
    //    - Use std::cout to verify packet counts match expected values
    //    - Print first few packets to understand structure
    //    - Check if packet count is non-zero before checking specifics
    //    - The doctest framework will show detailed mismatches
    //
    // REMEMBER: Implement both analyzeBasicStats() and 
    // analyzeLayerStats() in tests.cpp with this logic!


    // Close the file
    reader->close();
    delete reader;

    std::cout << "\nPCAP reader is initialized and ready for your analysis!" << std::endl;
    std::cout << "Now implement the two functions in tests.cpp:" << std::endl;
    std::cout << "  1. analyzeBasicStats() - Count protocol types" << std::endl;
    std::cout << "  2. analyzeLayerStats() - Analyze OSI layer distribution" << std::endl;

    return 0;
}
