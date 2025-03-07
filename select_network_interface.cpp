#include "packet_parser.h"

// 네트워크 장치 필터링 함수 (가상 장치 제외)
bool IsVirtualOrUnwanted(const std::string& desc);
// IPv4 주소 변환 함수
std::string ConvertIPv4(struct in_addr addr);

// IPv4 주소 변환 함수
std::string ConvertIPv4(struct in_addr addr) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

// 불필요한 네트워크 장치를 필터링하는 함수
bool IsVirtualOrUnwanted(const std::string& desc) {
    static const std::vector<std::string> unwanted_keywords = {
        "Virtual", "VMware", "VPN", "Hyper-V", "Bluetooth", "Loopback", "TAP", "Adapter"
    };

    for (const auto& keyword : unwanted_keywords) {
        if (desc.find(keyword) != std::string::npos) {
            return true; // 불필요한 가상 네트워크 장치
        }
    }
    return false;
}

// 최적의 네트워크 장치 선택 함수
pcap_if_t* SelectBestNetworkDevice(pcap_if_t* alldevs, char* errbuf) {
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "pcap_findalldevs 에러: " << errbuf << std::endl;
        return nullptr;
    }

    std::cout << "네트워크 인터페이스 목록:\n";

    std::vector<pcap_if_t*> ethernetDevices;
    pcap_if_t* selectedDevice = nullptr;

    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        std::string description = dev->description ? dev->description : "설명 없음";

        bool hasIPv4 = false;
        for (pcap_addr_t* a = dev->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                hasIPv4 = true;
                break;
            }
        }

        std::cout << "이름: " << dev->name << std::endl;
        std::cout << "설명: " << description << std::endl;
        std::cout << "-------------------------\n";

        // 실제 유선 이더넷만 필터링
        if (!IsVirtualOrUnwanted(description) && hasIPv4) {
            ethernetDevices.push_back(dev);
        }
    }

    // 유선 이더넷 우선 선택
    for (pcap_if_t* dev : ethernetDevices) {
        if (strstr(dev->description, "Ethernet") != nullptr) {
            selectedDevice = dev;
            break;
        }
    }

    // Wi-Fi는 후순위
    if (!selectedDevice) {
        for (pcap_if_t* dev : ethernetDevices) {
            if (strstr(dev->description, "Wi-Fi") != nullptr || strstr(dev->description, "Wireless") != nullptr) {
                selectedDevice = dev;
                break;
            }
        }
    }

    // 마지막으로 다른 네트워크 장치라도 선택
    if (!selectedDevice && !ethernetDevices.empty()) {
        selectedDevice = ethernetDevices.front();
    }

    if (!selectedDevice) {
        std::cerr << "이더넷 네트워크 장치를 찾을 수 없습니다." << std::endl;
        pcap_freealldevs(alldevs);
        return nullptr;
    }

    std::cout << "캡처에 사용할 네트워크 장치: " << selectedDevice->name << std::endl;

    return selectedDevice;
}