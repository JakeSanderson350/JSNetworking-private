#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <cstring>

namespace pcap {

// Network protocol identifiers
enum ProtocolType : uint16_t {
    Unknown = 0,
    Ethernet = 1,         // Layer 2: Ethernet
    ARP = 0x0806,         // Layer 3: Address Resolution Protocol
    IPv4 = 0x0800,        // Layer 3: Internet Protocol version 4
    IPv6 = 0x86DD,        // Layer 3: Internet Protocol version 6
    TCP = 6 | 0x1000,     // Layer 4: Transmission Control Protocol
    UDP = 17 | 0x1000,    // Layer 4: User Datagram Protocol
    ICMP = 1 | 0x1000,    // Layer 4: Internet Control Message Protocol
    ICMPv6 = 58 | 0x1000  // Layer 4: ICMP for IPv6
};

// Layer classes for getLayerOfType<T>() support
struct EthernetLayer {};
struct ARPLayer {};
struct IPv4Layer {};
struct IPv6Layer {};
struct TCPLayer {};
struct UDPLayer {};
struct ICMPLayer {};

// Raw packet data container
class RawPacket {
public:
    std::vector<uint8_t> data;
    uint32_t timestamp_sec = 0;
    uint32_t timestamp_usec = 0;
    uint32_t linkType = 1;  // Link layer type (1 = Ethernet, 113 = Linux cooked, etc.)

    const uint8_t* getData() const { return data.data(); }
    size_t getDataLen() const { return data.size(); }
};

// Parsed packet with protocol detection
class Packet {
private:
    const RawPacket* rawPacket_;
    bool hasEthernet_ = false;
    bool hasIPv4_ = false;
    bool hasIPv6_ = false;
    bool hasARP_ = false;
    bool hasTCP_ = false;
    bool hasUDP_ = false;
    bool hasICMP_ = false;
    
    void parsePacket() {
        if (!rawPacket_ || rawPacket_->getDataLen() < 14) return;
        
        const uint8_t* data = rawPacket_->getData();
        size_t len = rawPacket_->getDataLen();
        size_t offset = 0;
        uint16_t etherType = 0;
        
        // Parse based on link layer type
        if (rawPacket_->linkType == 1) {
            // Ethernet frame: [Dst MAC: 6][Src MAC: 6][EtherType: 2][Payload]
            if (len < 14) return;
            
            // Extract EtherType (bytes 12-13, big-endian)
            etherType = (data[12] << 8) | data[13];
            
            // Validate EtherType (must be >= 0x0600 for Ethernet II)
            if (etherType < 0x0600) return;
            
            // Only parse common protocols
            const bool isSupportedEtherType = (
                etherType == 0x0800 ||  // IPv4
                etherType == 0x0806 ||  // ARP
                etherType == 0x86DD ||  // IPv6
                etherType == 0x8100 ||  // VLAN
                etherType == 0x8035     // RARP
            );
            
            if (!isSupportedEtherType) return;
            
            hasEthernet_ = true;
            offset = 14;
            
            // Handle VLAN tags (EtherType 0x8100)
            while (etherType == 0x8100 && offset + 4 <= len) {
                etherType = (data[offset + 2] << 8) | data[offset + 3];
                offset += 4;
            }
        } else if (rawPacket_->linkType == 113) {
            // Linux cooked capture: 16-byte header
            if (len < 16) return;
            
            // Protocol type at bytes 14-15 (similar to EtherType)
            etherType = (data[14] << 8) | data[15];
            offset = 16;
        } else {
            // Unsupported link type
            return;
        }
        
        // Parse network and transport layer protocols
        
        if (etherType == 0x0800 && offset + 20 <= len) {
            // IPv4 packet
            hasIPv4_ = true;
            
            // Get protocol type (byte 9 of IPv4 header)
            uint8_t protocol = data[offset + 9];
            
            // Get header length (lower 4 bits of byte 0, in 32-bit words)
            uint8_t ihl = (data[offset] & 0x0F) * 4;
            offset += ihl;
            
            // Check transport layer protocol
            if (protocol == 6 && offset + 20 <= len) {
                hasTCP_ = true;
            } else if (protocol == 17 && offset + 8 <= len) {
                hasUDP_ = true;
            } else if (protocol == 1) {
                hasICMP_ = true;
            }
        } else if (etherType == 0x86DD && offset + 40 <= len) {
            // IPv6 packet (fixed 40-byte header)
            hasIPv6_ = true;
            
            // Get next header field (byte 6)
            uint8_t nextHeader = data[offset + 6];
            offset += 40;
            
            // Process extension headers to find transport protocol
            while (offset < len) {
                if (nextHeader == 6 && offset + 20 <= len) {
                    hasTCP_ = true;
                    break;
                } else if (nextHeader == 17 && offset + 8 <= len) {
                    hasUDP_ = true;
                    break;
                } else if (nextHeader == 58) {
                    hasICMP_ = true;
                    break;
                } else if (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || 
                           nextHeader == 51 || nextHeader == 60) {
                    // IPv6 extension header
                    if (offset + 2 > len) break;
                    uint8_t extLen = data[offset + 1];
                    nextHeader = data[offset];
                    offset += (extLen + 1) * 8;
                } else {
                    break;
                }
            }
        } else if (etherType == 0x0806) {
            // ARP packet
            hasARP_ = true;
        }
    }
    
public:
    Packet(const RawPacket* rawPacket) : rawPacket_(rawPacket) {
        parsePacket();
    }
    
    bool isPacketOfType(ProtocolType type) const {
        switch (type) {
            case Ethernet: return hasEthernet_;
            case IPv4: return hasIPv4_;
            case IPv6: return hasIPv6_;
            case ARP: return hasARP_;
            case TCP: return hasTCP_;
            case UDP: return hasUDP_;
            case ICMP: return hasICMP_;
            default: return false;
        }
    }
    
    // Generic getLayerOfType - returns nullptr for unsupported types
    template<typename T> T* getLayerOfType() { return nullptr; }
    
    // Specializations for supported layer types
    template<> EthernetLayer* getLayerOfType<EthernetLayer>() {
        return hasEthernet_ ? new EthernetLayer() : nullptr;
    }
    
    template<> IPv4Layer* getLayerOfType<IPv4Layer>() {
        return hasIPv4_ ? new IPv4Layer() : nullptr;
    }
    
    template<> IPv6Layer* getLayerOfType<IPv6Layer>() {
        return hasIPv6_ ? new IPv6Layer() : nullptr;
    }
    
    template<> ARPLayer* getLayerOfType<ARPLayer>() {
        return hasARP_ ? new ARPLayer() : nullptr;
    }
    
    template<> TCPLayer* getLayerOfType<TCPLayer>() {
        return hasTCP_ ? new TCPLayer() : nullptr;
    }
    
    template<> UDPLayer* getLayerOfType<UDPLayer>() {
        return hasUDP_ ? new UDPLayer() : nullptr;
    }
    
    template<> ICMPLayer* getLayerOfType<ICMPLayer>() {
        return hasICMP_ ? new ICMPLayer() : nullptr;
    }
};

// PCAP/PCAPNG file reader
class IFileReaderDevice {
private:
    std::ifstream file_;
    bool isPcapNG_ = false;
    uint32_t linkType_ = 1;
    bool swapBytes_ = false;
    std::vector<uint32_t> interfaceLinkTypes_;

    uint16_t swap16(uint16_t val) const {
        return swapBytes_ ? ((val << 8) | (val >> 8)) : val;
    }
    
    uint32_t swap32(uint32_t val) const {
        if (!swapBytes_) return val;
        return ((val << 24) | ((val << 8) & 0x00FF0000) | 
                ((val >> 8) & 0x0000FF00) | (val >> 24));
    }
    
    bool readPcapNGBlock(RawPacket& packet) {
        uint32_t blockType, blockLen;
        file_.read(reinterpret_cast<char*>(&blockType), 4);
        file_.read(reinterpret_cast<char*>(&blockLen), 4);
        
        if (!file_ || blockLen < 12) return false;
        
        blockType = swap32(blockType);
        blockLen = swap32(blockLen);
        
        if (blockType == 0x00000006) {
            // Enhanced Packet Block - contains packet data
            uint32_t interfaceId, capturedLen, packetLen;
            uint64_t timestamp;
            
            file_.read(reinterpret_cast<char*>(&interfaceId), 4);
            interfaceId = swap32(interfaceId);
            file_.read(reinterpret_cast<char*>(&timestamp), 8);
            file_.read(reinterpret_cast<char*>(&capturedLen), 4);
            file_.read(reinterpret_cast<char*>(&packetLen), 4);
            
            capturedLen = swap32(capturedLen);
            packet.data.resize(capturedLen);
            file_.read(reinterpret_cast<char*>(packet.data.data()), capturedLen);
            
            // Set link type based on interface
            if (interfaceId < interfaceLinkTypes_.size()) {
                packet.linkType = interfaceLinkTypes_[interfaceId];
            } else {
                packet.linkType = 1;
            }

            // Skip padding and options
            uint32_t padding = (4 - (capturedLen % 4)) % 4;
            uint32_t remainingBytes = blockLen - 28 - capturedLen - padding;
            file_.seekg(padding + remainingBytes, std::ios::cur);
            
            return file_.good();
        } else if (blockType == 0x00000001) {
            // Interface Description Block
            uint16_t linkType;
            file_.read(reinterpret_cast<char*>(&linkType), 2);
            linkType = swap16(linkType);
            interfaceLinkTypes_.push_back(linkType);

            file_.seekg(blockLen - 10, std::ios::cur);
            return readPcapNGBlock(packet);
        } else if (blockType == 0x0A0D0D0A) {
            // Section Header Block
            interfaceLinkTypes_.clear();
            file_.seekg(blockLen - 8, std::ios::cur);
            return readPcapNGBlock(packet);
        } else {
            // Other block types - skip
            file_.seekg(blockLen - 8, std::ios::cur);
            return readPcapNGBlock(packet);
        }
    }
    
public:
    static IFileReaderDevice* getReader(const std::string& filename) {
        auto* reader = new IFileReaderDevice();
        reader->file_.open(filename, std::ios::binary);
        if (!reader->file_) {
            delete reader;
            return nullptr;
        }
        return reader;
    }
    
    bool open() {
        if (!file_.is_open()) return false;
        
        // Read magic number to determine file format
        uint32_t magic;
        file_.read(reinterpret_cast<char*>(&magic), 4);
        
        if (magic == 0xA1B2C3D4) {
            // Classic PCAP format (native byte order)
            isPcapNG_ = false;
            swapBytes_ = false;
            
            file_.seekg(16, std::ios::cur);  // Skip header fields
            file_.read(reinterpret_cast<char*>(&linkType_), 4);
            linkType_ = swap32(linkType_);
            
        } else if (magic == 0xD4C3B2A1) {
            // Classic PCAP format (byte-swapped)
            isPcapNG_ = false;
            swapBytes_ = true;
            
            file_.seekg(16, std::ios::cur);
            file_.read(reinterpret_cast<char*>(&linkType_), 4);
            linkType_ = swap32(linkType_);
            
        } else if (magic == 0x0A0D0D0A) {
            // PCAPNG format (block-based)
            isPcapNG_ = true;
            file_.seekg(0, std::ios::beg);
        } else {
            return false;
        }
        
        return true;
    }
    
    bool getNextPacket(RawPacket& packet) {
        if (!file_) return false;
        
        if (isPcapNG_) {
            return readPcapNGBlock(packet);
        } else {
            // Classic PCAP format
            uint32_t ts_sec, ts_usec, incl_len, orig_len;
            
            file_.read(reinterpret_cast<char*>(&ts_sec), 4);
            file_.read(reinterpret_cast<char*>(&ts_usec), 4);
            file_.read(reinterpret_cast<char*>(&incl_len), 4);
            file_.read(reinterpret_cast<char*>(&orig_len), 4);
            
            if (!file_) return false;
            
            incl_len = swap32(incl_len);
            
            packet.data.resize(incl_len);
            file_.read(reinterpret_cast<char*>(packet.data.data()), incl_len);
            packet.linkType = linkType_;

            return file_.good();
        }
    }
    
    void close() {
        if (file_.is_open()) {
            file_.close();
        }
    }
    
    ~IFileReaderDevice() {
        close();
    }
};

} // namespace pcap

namespace pcpp = pcap;
