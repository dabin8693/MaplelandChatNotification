#include "packet_parser.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
// Ư�� ���μ���(PID)�� ����ϴ� TCP ��Ʈ ����� ��ȯ
std::vector<unsigned short> GetProcessPorts(DWORD pid) {
    std::vector<unsigned short> ports;

    // TCP ��Ʈ ��ȸ (IPv4)
    ULONG tcpSize = 0;

    // �ʿ��� ���� ũ�� Ȯ��
    if (GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "TCP ���̺� ũ�� ��ȸ ����" << std::endl;
        return ports;
    }

    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(tcpSize);
    if (!pTcpTable) {
        std::cerr << "TCP ���̺� �޸� �Ҵ� ����" << std::endl;
        return ports;
    }

    // TCP ���̺� ��������
    if (GetExtendedTcpTable(pTcpTable, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            if (pTcpTable->table[i].dwOwningPid == pid) {
                // ��Ʈ��ũ ����Ʈ ������ ȣ��Ʈ ����Ʈ ������ ��ȯ
                unsigned short port = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                ports.push_back(port);
            }
        }
    }
    free(pTcpTable);  // �޸� ����

    return ports;
}
