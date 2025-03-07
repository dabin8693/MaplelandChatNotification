#include "packet_parser.h"
#include <iomanip>  // std::hex, std::setw, std::setfill
// --- [ 전역 변수 정의 ] ---
const unsigned char recordPattern[] = { 0x54, 0x4f, 0x5a, 0x20 };
const unsigned char chatPattern[] = { 0x98, 0xac, 0x25, 0xcf, 0xff, 0xff, 0xff, 0xff, 0x00, 0x98, 0xac, 0x25, 0xcf, 0x01, 0x00, 0x00, 0x00,
0x71, 0x00, 0x00, 0x80 }; // 21 바이트
const unsigned char allChat[] = { 0x02, 0x00, 0x00, 0x00, 0x00 };
const unsigned char petChat_send[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
const unsigned char sameChat_receive[] = { 0x04, 0x00, 0x00, 0x00, 0x00 };
const unsigned char cashChat_receive[] = { 0x05, 0x00, 0x00, 0x00, 0x00 };
const unsigned char privateChat_send[] = { 0x0c, 0x00, 0x00, 0x00, 0x00 };
const unsigned char privateChat_receive[] = { 0x0d, 0x00, 0x00, 0x00, 0x00 };
// 전역변수 정의 및 초기화
const struct {
    const unsigned char* pattern;
    int type;
    const char* name;
} patterns[] = {
    { allChat, 1, "전체 채팅"},
    { petChat_send, 2, "펫 채팅(정확히는 잘 모름)"},
    { sameChat_receive, 3, "채널 채팅"},
    { cashChat_receive, 4, "고확"},
    { privateChat_send, 5, "귓속말(송신)"},
    { privateChat_receive, 6, "귓속말(수신)"}
};

struct record_buffer g_record_buffer = { // 레코드의 생명주기는 패킷과 다름으로 전역으로 선언
    nullptr , DEFAULT_INT_VALUE, DEFAULT_INT_VALUE, DEFAULT_INT_VALUE, DEFAULT_INT_VALUE
};

struct info g_info = {
    nullptr , nullptr , DEFAULT_INT_VALUE, std::string() , nullptr
};

int ParsePacket(const u_char* packet, int packet_len) {
    // 패킷정보 구조체는 지역변수로 선언
    packet_info p_info = { 0, 0 }; // 패킷정보라 생명주기는 ParsePacket를 따라감
    // 채팅과 관련없는 패킷 구분 및 페이로드 오프셋 구하기
    if(!GetPayloadOffset(packet, packet_len, &p_info)) return FAILURE;
    
    while (true) {
        int remaining_size = p_info.packet_len - p_info.payload_offset;
        // std::cout << "remain size: " << remaining_size << "  payload_offset: " << p_info.payload_offset << std::endl;
        // 패킷 다 읽었는지 체크
        if (p_info.packet_len - p_info.payload_offset <= 0) return SUCCESS;
        if (g_record_buffer.flag == EMPTY) { // 빈 레코드
            // 레코드 체크
            if (!IsRecord(packet + p_info.payload_offset)) { // 레코드가 아니면 패킷 폐기
                // std::cout << "레코드가 아닙니다.!!\n";
                RecordReset();
                return FAILURE;
            }
            // std::cout << "빈 레코드\n";
            if (p_info.packet_len < p_info.payload_offset + 7) { //레코드 헤더가 짤림
                // std::cout << "헤더 잘림\n";
                memcpy(g_record_buffer.buffer, &packet[p_info.payload_offset], remaining_size);
                p_info.payload_offset = p_info.packet_len; // 끝까지 도달
                g_record_buffer.flag = CUT_HEADER;
                g_record_buffer.used_size = remaining_size;
                return SUCCESS;
            }
            else {
                g_record_buffer.r_len = GetRecordSize(packet, &p_info.payload_offset);
                if (remaining_size < g_record_buffer.r_len) { //레코드 바디가 짤림
                    // std::cout << "바디 잘림\n";
                    memcpy(g_record_buffer.buffer, &packet[p_info.payload_offset], remaining_size);
                    p_info.payload_offset = p_info.packet_len; // 끝까지 도달
                    g_record_buffer.flag = CUT_BODY;
                    g_record_buffer.used_size = remaining_size;
                    return SUCCESS;
                }
                else { //레코드가 다 포함됨
                    // std::cout << "안잘림\n";
                    memcpy(g_record_buffer.buffer, &packet[p_info.payload_offset], g_record_buffer.r_len);
                    p_info.payload_offset += g_record_buffer.r_len; // 레코드 크기만큼 이동
                    g_record_buffer.flag = COMPLETE;
                    g_record_buffer.used_size = g_record_buffer.r_len; 
                    
                    // 레코드 파싱
                    if (!ParseRecord()) { // 채팅 레코드가 아님
                        // std::cout << "채팅 레코드가 아님\n";
                    }
                    RecordReset();
                    continue;
                }
            }
        }
        else if (g_record_buffer.flag == CUT_HEADER) { // 헤드가 짤린 레코드
            // std::cout << "이전에 헤더가 잘린 레코드\n";
            u_char t_buffer[8]; // 레코드 체크와 레코드 길이를 구하기 위한 임시 버퍼
            for (int i = 0; i < g_record_buffer.used_size; i++) {
                t_buffer[i] = g_record_buffer.buffer[i];
                // std::cout << "잘린 헤더1 index: " << i << std::endl;
            }
            int index = 0;
            for (int i = g_record_buffer.used_size; i < 8; i++) {
                t_buffer[i] = packet[p_info.payload_offset + index];
                // std::cout << "잘린 헤더2 index: " << i << std::endl;
                index += 1;
            }
            // 레코드 체크
            if (!IsRecord(t_buffer)) { // 레코드가 아니면 패킷 폐기
                // std::cout << "레코드가 아닙니다.!!\n";
                RecordReset();
                return FAILURE;
            }
            g_record_buffer.r_len = GetRecordSize(t_buffer, 0);
            // 뒷 부분만 채움
            if (remaining_size < g_record_buffer.r_len - g_record_buffer.used_size) { //레코드 바디가 짤림
                // std::cout << "바디가 잘림\n";
                memcpy(g_record_buffer.buffer + g_record_buffer.used_size, &packet[p_info.payload_offset], remaining_size);
                p_info.payload_offset = p_info.packet_len; // 끝까지 도달
                g_record_buffer.flag = CUT_BODY;
                g_record_buffer.used_size += remaining_size; // 이전꺼까지 포함해서 합산
                return SUCCESS;
            }
            else { //레코드가 다 포함됨
                // std::cout << "안잘림\n";
                memcpy(g_record_buffer.buffer + g_record_buffer.used_size, &packet[p_info.payload_offset], g_record_buffer.r_len - g_record_buffer.used_size);
                p_info.payload_offset += (g_record_buffer.r_len - g_record_buffer.used_size); // 레코드 짤린거 만큼 이동
                g_record_buffer.flag = COMPLETE;
                g_record_buffer.used_size = g_record_buffer.r_len;
                
                // 레코드 파싱
                if (!ParseRecord()) { // 채팅 레코드가 아님
                    // std::cout << "채팅 레코드가 아님\n";
                }
                RecordReset();
                continue;
            }
        }
        else if (g_record_buffer.flag == CUT_BODY) { // 바디가 짤린 레코드
            // 레코드 체크
            if (!IsRecord(g_record_buffer.buffer)) { // 레코드가 아니면 패킷 폐기
                // std::cout << "레코드가 아닙니다.!!\n";
                RecordReset();
                return FAILURE;
            }
            // 뒷 부분만 채움
            if (remaining_size < g_record_buffer.r_len - g_record_buffer.used_size) { //레코드 바디가 짤림
                memcpy(g_record_buffer.buffer + g_record_buffer.used_size, &packet[p_info.payload_offset], remaining_size);
                p_info.payload_offset = p_info.packet_len; // 끝까지 도달
                g_record_buffer.flag = CUT_BODY;
                g_record_buffer.used_size += remaining_size; // 이전꺼까지 포함해서 합산
                return SUCCESS;
            }
            else { //레코드가 다 포함됨
                memcpy(g_record_buffer.buffer + g_record_buffer.used_size, &packet[p_info.payload_offset], g_record_buffer.r_len - g_record_buffer.used_size);
                p_info.payload_offset += (g_record_buffer.r_len - g_record_buffer.used_size); // 레코드 짤린거 만큼 이동
                g_record_buffer.flag = COMPLETE;
                g_record_buffer.used_size = g_record_buffer.r_len;
                
                // 레코드 파싱
                if (!ParseRecord()) { // 채팅 레코드가 아님
                    // std::cout << "채팅 레코드가 아님\n";
                }
                RecordReset();
                continue;
            }
        }
        else {
            std::cout << "레코드 flag 에러 flage=" << g_record_buffer.flag << std::endl;
        }
        return FAILURE;
    }

    return FAILURE;
}

int ParseRecord() { // 여기부터 g_record_buffer.r_offset를 읽을 때마다 증가시킴
    if (!IsChat()) return FAILURE;
    int nickname_len = 0;
    int chat_len = 0;
    std::string type_name;
    int type = GetChatType();
    // UTF-8 → 콘솔 인코딩 변환
    if (GetNickname(&nickname_len) == 0) return FAILURE;
    std::string nickname = UTF8ToConsoleEncoding(g_info.nickname, nickname_len);

    if (GetChatContent(&chat_len) == 0) return FAILURE;
    std::string chat_content = UTF8ToConsoleEncoding(g_info.chat_content, chat_len);

    // 알림 설정
    CheckKeywordTrigger(chat_content, type);
    // std::cout << "닉네임 길이: " << nickname_len << " 채팅 길이: " << chat_len << std::endl;
    // 표준 출력
    std::cout << "<" << g_info.type_name << ">" << type_name << " 닉네임: " << nickname << "  내용: " << chat_content << std::endl;
    return SUCCESS;
}


void RecordReset() {
    g_record_buffer.r_len = DEFAULT_INT_VALUE;
    g_record_buffer.used_size = DEFAULT_INT_VALUE;
    g_record_buffer.r_offset = DEFAULT_INT_VALUE;
    g_record_buffer.flag = EMPTY;
    g_info.ch = NULL;
    g_info.chat_type = DEFAULT_INT_VALUE;
    g_info.type_name = std::string();
    g_info.chat_content = NULL;
    g_info.nickname = NULL;
    
}

void CheckKeywordTrigger(const std::string& text, int TYPE) {
    // std 콘솔 출력 빨간 글씨로 변경
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);

    if (text.find("어금니") != std::string::npos) { // "어금니"가 포함되어 있는지 확인
        isTrigger = 1;
        std::cout << "[!] 키워드 '어금니' 감지됨! 트리거 활성화\n";
    }
    if (TYPE == 6) {
        isTrigger = 1; // 귓말 왔을때 소리 알림
    }


    // 1귓말 알림 기능이 켜져 있고, TYPE이 6 (귓말 수신)일 경우
    if (whisper_alert && TYPE == 6) {
        isTrigger = true;
        std::cout << "[!] 귓말(수신) 감지됨! 트리거 활성화\n";
    }

    // 키워드 검사: TYPE이 키워드의 타입과 일치할 때만 트리거 활성화
    for (const auto& kw : keywords) {
        if (kw.type == TYPE && text.find(kw.word) != std::string::npos) {
            isTrigger = true;
            std::cout << "[!] 키워드 '" << kw.word << "' 감지됨! (타입: " << kw.type << ") 트리거 활성화\n";
        }
    }
    // std 콘솔 출력 색깔 원상복구
    SetConsoleTextAttribute(hConsole, defaultColor);
}

int GetNickname(int* nickname_len) {
    int TYPE = g_info.chat_type;
    u_char *buffer = g_record_buffer.buffer;
    int offset = g_record_buffer.r_offset;
    if (TYPE == 1) {
        // entity 길이 오프셋 이동
        offset += 6;
        // entity 길이(리틀 엔디안, 4바이트)
        int e_len = GetSize(buffer, offset);
        if (e_len > MAX_ENTITY_LENGTH) return FAILURE;
        // entity 문자열 오프셋 이동
        offset += 4;
        // EOT 오프셋 이동
        offset += e_len;
        // 닉네임 길이 오프셋 이동
        offset += 2;
        // 닉네임 길이(리틀 엔디안, 4바이트)
        *nickname_len = GetSize(buffer, offset);
        if (*nickname_len > MAX_NAME_LENGTH) return FAILURE;
        // 닉네임 문자열 오프셋 이동
        offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        g_info.nickname = buffer + offset;
        // PrintHex(packet, *nickname_len, offset);
        offset += *nickname_len;
        g_record_buffer.r_offset = offset;
        return SUCCESS;
    }
    else if (TYPE == 5) {
        return FAILURE;
        // entity 길이 오프셋 이동
        offset += 6;
        // entity 길이(리틀 엔디안, 4바이트)
        int e_len = GetSize(buffer, offset);
        if (e_len > MAX_ENTITY_LENGTH) return FAILURE;
        // entity 문자열 오프셋 이동
        offset += 4;
        // EOT 오프셋 이동
        offset += e_len;
        
        // 여기부터 닉네임과 채팅의 위치가 바뀜
        // 난중에 완성

        g_record_buffer.r_offset = offset;
    }
    else if (TYPE ==3 or TYPE == 4 or TYPE == 6) {
        // 닉네임 길이 오프셋 이동
        offset += 6;
        // 닉네임 길이(리틀 엔디안, 4바이트)
        *nickname_len = GetSize(buffer, offset);
        if (*nickname_len > MAX_NAME_LENGTH) return FAILURE;
        // 닉네임 문자열 오프셋 이동
        offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        g_info.nickname = buffer + offset;
        // PrintHex(packet, *nickname_len, offset);
        offset += *nickname_len;
        g_record_buffer.r_offset = offset;
        return SUCCESS;
    }
    else {
        return FAILURE;
    }
}

int GetChatContent(int* chat_len) {
    int TYPE = g_info.chat_type;
    u_char* buffer = g_record_buffer.buffer;
    int offset = g_record_buffer.r_offset;
    if (TYPE == 4 or TYPE == 1) {
        // 채팅 길이 오프셋 이동
        offset += 2;
        // 채팅 길이(리틀 엔디안, 4바이트)
        *chat_len = GetSize(buffer, offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // 채팅 문자열 오프셋 이동
        offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        g_info.chat_content = buffer + offset;
        offset += *chat_len;
        g_record_buffer.r_offset = offset;
        return SUCCESS;
    }
    else if (TYPE == 3) {
        // 채팅 길이 오프셋 이동
        offset += 2;
        // 채팅 길이(리틀 엔디안, 4바이트)
        *chat_len = GetSize(buffer, offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // 채팅 문자열 오프셋 이동
        offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        g_info.chat_content = buffer + offset;
        offset += *chat_len;
        g_record_buffer.r_offset = offset;
        return SUCCESS;
    }
    else if (TYPE == 5) {
        return 0;
        // 채팅과 닉네임의 위치가 바뀜
    }
    else if (TYPE == 6) {
        // 채널 길이 오프셋 이동
        offset += 2;
        // 채널 길이 오프셋 이동(리틀 엔디안, 4바이트)
        int c_len = GetSize(buffer, offset);
        if (c_len > MAX_CHANNEL_LENGTH) return 0;
        // 채널 문자열 오프셋 이동
        offset += 4;
        // EOT 오프셋 이동
        offset += c_len;
        // 채팅 길이 오프셋 이동
        offset += 2;
        // 채팅 길이(리틀 엔디안, 4바이트)
        *chat_len = GetSize(buffer, offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // 채팅 문자열 이동
        offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        g_info.chat_content = buffer + offset;
        offset += *chat_len;
        g_record_buffer.r_offset = offset;
        return SUCCESS;
    }
    else {
        return 0;
    }
}

int GetChatType() {
    // std::cout << "챗타입검사 전 레코드offset: " << g_record_buffer.r_offset << std::endl;
    int num_patterns = sizeof(patterns) / sizeof(patterns[0]);
    for (int i = 0; i < num_patterns; i++) {
        if (memcmp(g_record_buffer.buffer + g_record_buffer.r_offset, patterns[i].pattern, 5) == 0) {
            g_record_buffer.r_offset += 5;
            g_info.chat_type = patterns[i].type;
            g_info.type_name = patterns[i].name;
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "채팅 종류는 " << patterns[i].name << " 입니다." << std::endl;
            SetConsoleTextAttribute(hConsole, defaultColor);
            return patterns[i].type;
        }
    }
    
    std::cout << "채팅 종류는 알 수 없음 입니다." << std::endl;
    return FAILURE;
}

int IsChat()
{
    g_record_buffer.r_offset += 17; 
    if (memcmp(g_record_buffer.buffer + g_record_buffer.r_offset, chatPattern, sizeof(chatPattern)) == 0) {
        std::cout << "-------------------" << std::endl;
        std::cout << "채팅 패턴이 오프셋" << g_record_buffer.r_offset << "에서 발견되었습니다." << std::endl;
        g_record_buffer.r_offset += sizeof(chatPattern); // chatPattern = 21바이트
        return SUCCESS;
    }
    else {
        // PrintHex(g_record_buffer.buffer + g_record_buffer.r_offset, 21);
        g_record_buffer.r_offset += sizeof(chatPattern);
        // std::cout << "챗인지검사 후 레코드offset: " << g_record_buffer.r_offset << std::endl;
        // std::cout << "알수 없는 바이트 패턴입니다." << std::endl;
        return FAILURE;
    }
}

// little-endian 4바이트 길이 구하기
int GetSize(const u_char* packet, int start_offset) {
    int size = packet[start_offset] | (packet[start_offset + 1] << 8) |
        (packet[start_offset + 2] << 16) | (packet[start_offset + 3] << 24);
    return size;
}

int GetRecordSize(const u_char *packet, int* p_offset) { // 패킷에서 읽을때
    int size = GetSize(packet, *p_offset + 4) + 25; // 25번째 오프셋부터 길이안에 포함됨
    // std::cout << "패킷에서 읽은 레코드 사이즈: " << size << std::endl;
    return size;
}

int GetRecordSize(const u_char* r_buffer, int offset) { // 레코드 버퍼에서 읽을때
    int size = GetSize(r_buffer, offset + 4) + 25; // 25번째 오프셋부터 길이안에 포함됨
    // std::cout << "버퍼에서 읽은 레코드 사이즈: " << size << std::endl;
    return size;
}

int IsRecord(const u_char* buffer) {
    if (memcmp(buffer, recordPattern, sizeof(recordPattern)) == 0) {
        // std::cout << "레코드O " << std::endl;
        return SUCCESS;
    }
    // std::cout << "레코드X " << std::endl;
    // PrintHex(buffer, 4);
    return FAILURE;
}

int GetPayloadOffset(const u_char* packet, int packet_len, struct packet_info *packet_info)
{
    const int ethernet_header_length = 14;
    if (packet_len < ethernet_header_length) return FAILURE;

    const struct ether_header* eth_hdr = (const struct ether_header*)packet;
    // IPv6면 다음 사이클로 넘어감
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return FAILURE;

    const struct ip_header* ip_hdr = (const struct ip_header*)(packet + ethernet_header_length);
    int ip_header_length = (ip_hdr->version_ihl & 0x0F) * 4;

    if (packet_len < ethernet_header_length + ip_header_length) return FAILURE;
    // IPv6면 다음 사이클로 넘어감
    if (ip_hdr->protocol != IPPROTO_TCP) return FAILURE;

    uint16_t mf_bit = (ntohs(ip_hdr->flags_offset) & 0x2000) >> 13; // MF 비트 추출
    uint16_t fragment_offset = (ntohs(ip_hdr->flags_offset) & 0x1FFF); // Fragment Offset 추출
    // MF bit 가 1이면 분할 패킷이므로 다음 사이클로 넘어감(게임 리소스 데이터만 분할되어서 옴)(채팅패킷 분석에는 필요x)
    if (mf_bit) {
        std::cout << "ip패킷이 조각났습니다." << std::endl;
        return FAILURE;
    }
    else {
        // 분할된 패킷의 마지막 패킷이므로 다음 사이클로 넘어감
        if (fragment_offset) {
            std::cout << "조각난 ip패킷의 마지막 조각입니다. 조각 번호 : " << fragment_offset << std::endl;
            return FAILURE;
        }
    }
    // IPv4 패킷 크기 검증
    uint16_t ip_total_length = ntohs(ip_hdr->total_length);

    const struct tcp_header* tcp_hdr = (const struct tcp_header*)(packet + ethernet_header_length + ip_header_length);
    // 데이터 오프셋 4비트를 확인해서 실제 tcp헤더의 크기 구하기
    int tcp_header_length = ((tcp_hdr->offset_reserved >> 4) & 0x0F) * 4;
    
    packet_info->payload_offset = ethernet_header_length + ip_header_length + tcp_header_length;
    packet_info->packet_len = packet_len;
    return packet_info->payload_offset;
}

// --- [ UTF-8 → 콘솔 기본 인코딩(CP949 등) 변환 함수 ] ---
std::string UTF8ToConsoleEncoding(const u_char* utf8_str_b, size_t length) {
    if (utf8_str_b == NULL || length == 0) return ""; // NULL 체크 및 빈 문자열 처리
    
    // UTF-8 → UTF-16 변환
    int wlen = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(utf8_str_b), static_cast<int>(length), NULL, 0);
    if (wlen == 0) return "";

    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(utf8_str_b), static_cast<int>(length), &wstr[0], wlen);

    // UTF-16 → 콘솔 기본 인코딩 변환 (CP949 등)
    int mblen = WideCharToMultiByte(GetConsoleOutputCP(), 0, wstr.c_str(), wlen, NULL, 0, NULL, NULL);
    if (mblen == 0) return "";

    std::string console_str(mblen, 0);
    WideCharToMultiByte(GetConsoleOutputCP(), 0, wstr.c_str(), wlen, &console_str[0], mblen, NULL, NULL);

    return console_str;
}

void PrintHex(const u_char* buffer, int length) {
    std::cout << "현재 출력할 총 길이: " << length << std::endl;
    for (int i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
    }
    std::cout << std::dec << std::endl;  // 10진수 출력으로 복구
}