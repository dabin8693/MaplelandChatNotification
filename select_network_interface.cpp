#include "packet_parser.h"

// ��Ʈ��ũ ��ġ ���͸� �Լ� (���� ��ġ ����)
bool IsVirtualOrUnwanted(const std::string& desc);
// IPv4 �ּ� ��ȯ �Լ�
std::string ConvertIPv4(struct in_addr addr);

// IPv4 �ּ� ��ȯ �Լ�
std::string ConvertIPv4(struct in_addr addr) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

// ���ʿ��� ��Ʈ��ũ ��ġ�� ���͸��ϴ� �Լ�
bool IsVirtualOrUnwanted(const std::string& desc) {
    static const std::vector<std::string> unwanted_keywords = {
        "Virtual", "VMware", "VPN", "Hyper-V", "Bluetooth", "Loopback", "TAP", "Adapter"
    };

    for (const auto& keyword : unwanted_keywords) {
        if (desc.find(keyword) != std::string::npos) {
            return true; // ���ʿ��� ���� ��Ʈ��ũ ��ġ
        }
    }
    return false;
}

// ������ ��Ʈ��ũ ��ġ ���� �Լ�
pcap_if_t* SelectBestNetworkDevice(pcap_if_t* alldevs, char* errbuf) {
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "pcap_findalldevs ����: " << errbuf << std::endl;
        return nullptr;
    }

    std::cout << "��Ʈ��ũ �������̽� ���:\n";

    std::vector<pcap_if_t*> ethernetDevices;
    pcap_if_t* selectedDevice = nullptr;

    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        std::string description = dev->description ? dev->description : "���� ����";

        bool hasIPv4 = false;
        for (pcap_addr_t* a = dev->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                hasIPv4 = true;
                break;
            }
        }

        std::cout << "�̸�: " << dev->name << std::endl;
        std::cout << "����: " << description << std::endl;
        std::cout << "-------------------------\n";

        // ���� ���� �̴��ݸ� ���͸�
        if (!IsVirtualOrUnwanted(description) && hasIPv4) {
            ethernetDevices.push_back(dev);
        }
    }

    // ���� �̴��� �켱 ����
    for (pcap_if_t* dev : ethernetDevices) {
        if (strstr(dev->description, "Ethernet") != nullptr) {
            selectedDevice = dev;
            break;
        }
    }

    // Wi-Fi�� �ļ���
    if (!selectedDevice) {
        for (pcap_if_t* dev : ethernetDevices) {
            if (strstr(dev->description, "Wi-Fi") != nullptr || strstr(dev->description, "Wireless") != nullptr) {
                selectedDevice = dev;
                break;
            }
        }
    }

    // ���������� �ٸ� ��Ʈ��ũ ��ġ�� ����
    if (!selectedDevice && !ethernetDevices.empty()) {
        selectedDevice = ethernetDevices.front();
    }

    if (!selectedDevice) {
        std::cerr << "�̴��� ��Ʈ��ũ ��ġ�� ã�� �� �����ϴ�." << std::endl;
        pcap_freealldevs(alldevs);
        return nullptr;
    }

    std::cout << "ĸó�� ����� ��Ʈ��ũ ��ġ: " << selectedDevice->name << std::endl;

    return selectedDevice;
}