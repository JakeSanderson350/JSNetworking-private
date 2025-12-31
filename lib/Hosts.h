//
// Created by tolstenko on 10/13/25.
//

#ifndef GG_NETWORK_IP_H
#define GG_NETWORK_IP_H
#include <string>

class Hosts {
public:
    static bool is_valid_ip(const std::string& ip_address);
    static bool is_valid_hostname(const std::string& hostname);
    static bool contains_entry(const std::string& hostname);
    static std::string get_ip(const std::string& hostname);
};


#endif //GG_NETWORK_IP_H