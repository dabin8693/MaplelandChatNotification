#include "packet_parser.h"
#include <tlhelp32.h>
#include <pcap.h>
#include <io.h>
#include <fcntl.h>


// `msw.exe`의 PID를 자동으로 찾는 함수
DWORD GetProcessID(const char* processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return SUCCESS;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            // pe.szExeFile이 `wchar_t[]`이므로, `char[]`로 변환해야 함
            char exeFile[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeFile, MAX_PATH, nullptr, nullptr);

            if (_stricmp(exeFile, processName) == 0) { // 변환 후 비교
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// 패킷 통계 정보 출력 함수 추가
void PrintPacketStats(pcap_t* handle) {
    struct pcap_stat stats;
    if (pcap_stats(handle, &stats) == 0) {
        std::cout << "[패킷 통계]" << std::endl;
        std::cout << "  - 캡처된 패킷: " << stats.ps_recv << std::endl;
        std::cout << "  - 버퍼에 남아있는 패킷: " << stats.ps_drop << std::endl;
        std::cout << "  - 드라이버에서 버려진 패킷: " << stats.ps_ifdrop << std::endl;
        std::cout << "---------------------------" << std::endl;
    }
    else {
        std::cerr << "패킷 통계 정보를 가져오는 데 실패했습니다: " << pcap_geterr(handle) << std::endl;
    }
}


void Initialize() {
    // SetConsoleOutputCP(CP_UTF8); // 콘솔 코드 페이지 UTF-8로 변경
    // _setmode(_fileno(stdout), _O_U16TEXT); // `wcout`을 UTF-16 모드로 설정 (영어 깨짐 방지)
    // 전역 변수 초기화 //
    // 콘솔 핸들 가져오기
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    // 기존 콘솔 색상 저장
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    defaultColor = consoleInfo.wAttributes;
    r_buffer = (u_char*)malloc(BUFFER_SIZE);
    // 레코드 버퍼 설정
    g_record_buffer.buffer = r_buffer;
    
}

// 전역변수 초기화 및 선언
uint8_t isRunning = 1;
uint8_t isTrigger = 0;
std::thread alertThread;

u_char* r_buffer;
HANDLE hConsole; // 콘솔 핸들 가져오기
WORD defaultColor; // 기본 콘솔 색상

int main() {
    
    Initialize();

    const char* targetProcess = "msw.exe";

    // `msw.exe`의 PID 찾기
    DWORD pid = GetProcessID(targetProcess);
    if (pid == 0) {
        std::cerr << targetProcess << " 프로세스를 찾을 수 없습니다." << std::endl;
        return FAILURE;
    }

    std::cout << targetProcess << "의 PID: " << pid << std::endl;

    // 프로세스의 TCP 포트 목록 가져오기
    std::vector<unsigned short> ports = GetProcessPorts(pid);
    if (ports.empty()) {
        std::cerr << "프로세스 " << pid << "에 해당하는 TCP 포트를 찾을 수 없습니다." << std::endl;
        return FAILURE;
    }

    std::cout << "프로세스 " << pid << "의 TCP 포트: ";
    for (unsigned short p : ports) {
        std::cout << p << " ";
    }
    std::cout << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    pcap_if_t* dev = nullptr;
    // 네트워크 인터페이스 자동 선택하기
    if((dev = SelectBestNetworkDevice(alldevs, errbuf)) == nullptr) return FAILURE;
    
    // 선택한 네트워크 장치를 열기
    pcap_t* handle = pcap_open_live(dev->name, 65536, 0, 1000, errbuf);
    // 1 : 송수신 0 : 수신
    if (handle == nullptr) {
        std::cerr << "장치 " << dev->name << "를 열 수 없습니다: " << errbuf << std::endl;
        return FAILURE;
    }
    // 소리알림 스레드 실행
    alertThread = std::thread(alertSoundLoop);
    // 알림 키워드 파싱
    LoadKeywords();
    // TCP 포트 필터 생성 (UDP 제거, TCP만 포함)
    std::ostringstream filterStream;
    filterStream << "tcp and (";
    bool first = true;
    for (unsigned short p : ports) {
        if (!first) {
            filterStream << " or ";
        }
        filterStream << "port " << p;
        first = false;
    }
    filterStream << ")";
    std::string filterExp = filterStream.str();
    std::cout << "필터 식: " << filterExp << std::endl;

    // 필터 적용
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filterExp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "필터 컴파일 실패 (" << filterExp << "): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return FAILURE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "필터 적용 실패 (" << filterExp << "): " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return FAILURE;
    }
    pcap_freecode(&fp);
    pcap_freealldevs(alldevs);

    // 패킷 캡처 시작
    std::cout << "패킷 캡처 시작..." << std::endl;
    int packet_count = 0;
    int timeout_count = 0;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) {
            timeout_count += 1;
            if (timeout_count > 100) {
                std::cout << "타임아웃 초과로 인해 종료 count : " << timeout_count  << std::endl;
                break;  // 종료
            }  
            continue;  // 타임아웃 - 계속 대기
        }
        else {
            timeout_count = 0; // 초기화
        }
        if (res == -1 || res == -2) {
            std::cout << "캡쳐 에러로 인해 종료 에러 코드 : " << res << std::endl;
            break;  // 종료
        }

        // std::cout << "캡처된 패킷 길이: " << header->len << std::endl;
#ifdef _DEBUG
        packet_count++;
#endif // DEBUG
        int flag = ParsePacket(packet, header->len);  // 패킷 분석 함수 호출
        // chat_packet_count += flag;
        
#ifdef _DEBUG
        if (packet_count % 2000 == 0) {  // 1000개 캡처할 때마다 상태 출력
            packet_count = 0;
            PrintPacketStats(handle);
        }
#endif // DEBUG
    }

    pcap_close(handle);
    free(r_buffer);
    return SUCCESS;
}


