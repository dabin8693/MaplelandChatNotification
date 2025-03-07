#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <thread>
#include <atomic>
#include <chrono>


// --- [ 상수 정의 ] ---
#define ETHERTYPE_IP 0x0800   /* IPv4 */
#define ETHERTYPE_ARP 0x0806  /* ARP */
#define ETHERTYPE_IPV6 0x86DD /* IPv6 */
#define IPPROTO_TCP 6         /* TCP */
#define BUFFER_SIZE 2048
// utf8 : 문자당 1~4바이트
#define MAX_NAME_LENGTH 64
// 메랜은 채팅64자까지 입력가능
#define MAX_CHAT_LENGTH 512
#define MAX_ENTITY_LENGTH 256
#define MAX_CHANNEL_LENGTH 64
// 초기값 정의
#define DEFAULT_INT_VALUE 0
// return값 정의
#define FAILURE 0
#define SUCCESS 1
// 레코드 상태 flag값 정의
#define EMPTY 0 /* 초기화 */
#define CUT_HEADER 1 /* 레코드 0~7오프셋 짤린경우 */
#define CUT_BODY 2 /* 레코드 7오프셋 이후 데이터가 짤린경우 */
#define COMPLETE 3 /* 완성된 레코드 */
// --- [ 전역 변수 선언 ] ---

extern const unsigned char chatPattern[];
extern const unsigned char allChat_send[];
extern const unsigned char petChat_send[];
extern const unsigned char sameChat_receive[];
extern const unsigned char cashChat_receive[];
extern const unsigned char privateChat_send[];
extern const unsigned char privateChat_receive[];

extern struct record_buffer g_record_buffer;
extern struct info g_info;

extern u_char* r_buffer;
extern uint8_t isRunning;
extern uint8_t isTrigger;
extern HANDLE hConsole; // 콘솔 핸들 가져오기
extern WORD defaultColor; // 기본 콘솔 색상

// 키워드 구조체
struct Keyword {
    int type;
    std::string word;
};
// 전역 변수 선언 (extern 사용)
extern bool whisper_alert;
extern std::vector<Keyword> keywords;
// --- [ 구조체 정의 ] ---
// Ethernet 헤더
struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};

// IPv4 헤더
struct ip_header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

// TCP 헤더
struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  offset_reserved;
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct packet_info {
    int packet_len; // ip패킷 총 크기
    int payload_offset; // tcp페이로드 읽어야 될 위치(이동은 레코드르 다 읽을때)
};

// 레코드 버퍼(54 4f 5a 20)부터 시작하는 1사이클 데이터
// len == position 이면 버퍼에 온전한 레코드1개가 담김
struct record_buffer {
    u_char* buffer;  // 2048 바이트의 고정 버퍼
    int r_len;       // 레코드 길이
    int used_size;   // 버퍼가 쓰여진 사이즈
    int r_offset;    // 버퍼를 읽어야 될 위치(읽을때마다 이동됨)
    int flag;        // 레코드버퍼 상태flag
};
//  EMPTY 0         초기화
//  CUT_HEADER 1    레코드 0~7오프셋 짤린경우 
//  CUT_BODY 2      레코드 7오프셋 이후 데이터가 짤린경우 
//  COMPLETE 3      완성된 레코드 

struct info {
    u_char* nickname;
    u_char* ch;
    int chat_type;
    std::string type_name;
    u_char* chat_content;
};

// --- [ 함수 선언 ] ---
extern std::vector<unsigned short> GetProcessPorts(DWORD pid);

extern pcap_if_t* SelectBestNetworkDevice(pcap_if_t* alldevs, char* errbuf);

extern void LoadKeywords();

extern int ParsePacket(const u_char* packet, int packet_len);
extern int ParseRecord();
extern int GetPayloadOffset(const u_char* packet, int packet_len, struct packet_info* packet_info);
extern int GetRecordSize(const u_char* packet, int* p_offset);
extern int GetRecordSize(const u_char* r_buffer, int offset);
extern int GetSize(const u_char* packet, int start_offset);
extern int GetChatType();
extern int GetNickname(int* nickname_len);
extern int GetChatContent(int* chat_len);
extern int IsChat();
extern int IsRecord(const u_char* buffer);
//extern int IsRecord(u_char* buffer);
extern std::string UTF8ToConsoleEncoding(const u_char* utf8_str_b, size_t length);
extern void CheckKeywordTrigger(const std::string& text, int TYPE);
extern void RecordReset();
extern int RecordKeywordCheck(int offset, const u_char* packet, int packet_len);
extern void PrintHex(const u_char* buffer, int length);

extern void alertSoundLoop();

#endif // PACKET_PARSER_H
