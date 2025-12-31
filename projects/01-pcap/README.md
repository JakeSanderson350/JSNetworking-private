# Repo Setup Assignment

We will use the ultimate pcap file from [Weberblog](https://weberblog.net/the-ultimate-pcap/). If the link is broken, use the [Wayback Machine](https://web.archive.org/web/20210101000000/https://weberblog.net/the-ultimate-pcap/) to find an archived version of the page. Direct link to the pcap file: [The-Ultimate-PCAP.7z](https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.7z).

If everything works correctly, the cmake will download and extract the pcap file into the `data/` folder.

## Requirements

- CMake 3.20 or higher
- 7-Zip (for extracting the .7z file)
    - macOS: brew install 7zip
    - Linux: sudo apt install p7zip-full (Debian/Ubuntu) or equivalent
    - Windows: Install 7-Zip to the default location (C:\Program Files\7-Zip)
- C++ compiler (GCC, Clang, MSVC, etc.) recognized by CMake

## Taking screenshots:

- **Windows** use the Snipping Tool or Snip & Sketch. Use `Win + Shift + S` to open the snipping toolbar.
- **macOS** use `Cmd + Shift + 5` to open the screenshot toolbar. Select the desired screenshot option. Hit enter to capture. The screenshot will be saved to your desktop by default. Copy it to the desired location.
- **Linux** if you use linux, you already know how to take screenshots. Use your preferred method. Love ya.

## Screenshots (4 points)

1. Your private repository's main page showing the repository name and that it is private. Name it `repo_name.png`.
2. The "Actions" tab of your private repository showing that GitHub Actions is enabled and at least the first one is passing. Name it `actions_enabled.png`.
3. The "Collaborators" settings page showing that your instructor has been added as a collaborator. Name it `collaborators.png`.
4. Your IDE showing you have disabled AI code completion features (if applicable). Name it `ai_disabled.png`.

All screenshots should be placed in this very own `01-pcap/` directory. At the same level as this README.md file. 

## Coding (4 points)

Go to the `tests` directory and fill the requirements. CI/CD will generate a report on the root folder `reports`.

### Task 1: Basic Packet Statistics (3 points)

Count and report the following:

| Metric | Description |
|--------|-------------|
| Total packets | Number of packets in the capture |
| IPv4 packets | Packets containing an IPv4 layer |
| IPv6 packets | Packets containing an IPv6 layer |
| TCP segments | Packets containing a TCP layer |
| UDP datagrams | Packets containing a UDP layer |
| ARP packets | Packets containing an ARP layer |
| ICMP packets | Packets containing an ICMP layer |

### Task 2: Layer Analysis (3 points)

For this task, you'll analyze how protocols distribute across OSI layers:

| Layer | Protocols to Count |
|-------|-------------------|
| Layer 2 (Data Link) | Ethernet |
| Layer 3 (Network) | IPv4, IPv6, ARP |
| Layer 4 (Transport) | TCP, UDP, ICMP |

This reinforces the concept that each packet is an encapsulation of multiple protocol layers.

### Expected Results

When you implement the functions correctly, your tests should pass with these values:

**Task 1:**
```
Total packets: 48640
IPv4 packets:  4065
IPv6 packets:  1283
TCP packets:   1726
UDP packets:   2660
ARP packets:   56
ICMP packets:  45
```

**Task 2:**
```
Layer 2 - Ethernet: 5264
Layer 3 - IPv4:     4065
Layer 3 - IPv6:     1283
Layer 3 - ARP:      56
Layer 4 - TCP:      1726
Layer 4 - UDP:      2660
Layer 4 - ICMP:     45
```

