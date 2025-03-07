#include "packet_parser.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
// 특정 프로세스(PID)가 사용하는 TCP 포트 목록을 반환
std::vector<unsigned short> GetProcessPorts(DWORD pid) {
    std::vector<unsigned short> ports;

    // TCP 포트 조회 (IPv4)
    ULONG tcpSize = 0;

    // 필요한 버퍼 크기 확인
    if (GetExtendedTcpTable(nullptr, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "TCP 테이블 크기 조회 실패" << std::endl;
        return ports;
    }

    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(tcpSize);
    if (!pTcpTable) {
        std::cerr << "TCP 테이블 메모리 할당 실패" << std::endl;
        return ports;
    }

    // TCP 테이블 가져오기
    if (GetExtendedTcpTable(pTcpTable, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            if (pTcpTable->table[i].dwOwningPid == pid) {
                // 네트워크 바이트 순서를 호스트 바이트 순서로 변환
                unsigned short port = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                ports.push_back(port);
            }
        }
    }
    free(pTcpTable);  // 메모리 해제

    return ports;
}
