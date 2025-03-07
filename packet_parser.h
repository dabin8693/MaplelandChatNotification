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


// --- [ ��� ���� ] ---
#define ETHERTYPE_IP 0x0800   /* IPv4 */
#define ETHERTYPE_ARP 0x0806  /* ARP */
#define ETHERTYPE_IPV6 0x86DD /* IPv6 */
#define IPPROTO_TCP 6         /* TCP */
#define BUFFER_SIZE 2048
// utf8 : ���ڴ� 1~4����Ʈ
#define MAX_NAME_LENGTH 64
// �޷��� ä��64�ڱ��� �Է°���
#define MAX_CHAT_LENGTH 512
#define MAX_ENTITY_LENGTH 256
#define MAX_CHANNEL_LENGTH 64
// �ʱⰪ ����
#define DEFAULT_INT_VALUE 0
// return�� ����
#define FAILURE 0
#define SUCCESS 1
// ���ڵ� ���� flag�� ����
#define EMPTY 0 /* �ʱ�ȭ */
#define CUT_HEADER 1 /* ���ڵ� 0~7������ ©����� */
#define CUT_BODY 2 /* ���ڵ� 7������ ���� �����Ͱ� ©����� */
#define COMPLETE 3 /* �ϼ��� ���ڵ� */
// --- [ ���� ���� ���� ] ---

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
extern HANDLE hConsole; // �ܼ� �ڵ� ��������
extern WORD defaultColor; // �⺻ �ܼ� ����

// Ű���� ����ü
struct Keyword {
    int type;
    std::string word;
};
// ���� ���� ���� (extern ���)
extern bool whisper_alert;
extern std::vector<Keyword> keywords;
// --- [ ����ü ���� ] ---
// Ethernet ���
struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};

// IPv4 ���
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

// TCP ���
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
    int packet_len; // ip��Ŷ �� ũ��
    int payload_offset; // tcp���̷ε� �о�� �� ��ġ(�̵��� ���ڵ帣 �� ������)
};

// ���ڵ� ����(54 4f 5a 20)���� �����ϴ� 1����Ŭ ������
// len == position �̸� ���ۿ� ������ ���ڵ�1���� ���
struct record_buffer {
    u_char* buffer;  // 2048 ����Ʈ�� ���� ����
    int r_len;       // ���ڵ� ����
    int used_size;   // ���۰� ������ ������
    int r_offset;    // ���۸� �о�� �� ��ġ(���������� �̵���)
    int flag;        // ���ڵ���� ����flag
};
//  EMPTY 0         �ʱ�ȭ
//  CUT_HEADER 1    ���ڵ� 0~7������ ©����� 
//  CUT_BODY 2      ���ڵ� 7������ ���� �����Ͱ� ©����� 
//  COMPLETE 3      �ϼ��� ���ڵ� 

struct info {
    u_char* nickname;
    u_char* ch;
    int chat_type;
    std::string type_name;
    u_char* chat_content;
};

// --- [ �Լ� ���� ] ---
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
