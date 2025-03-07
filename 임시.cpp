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

struct record_buffer global_record_buffer = {
    nullptr, DEFAULT_INT_VALUE, 0, 0,nullptr
};

struct info global_info = {
    nullptr, nullptr, DEFAULT_INT_VALUE
};

int ParsePacket(const u_char* packet, int packet_len) {
    // 패킷정보 구조체는 지역변수로 선언
    packet_info packet_info = { 0, 0 };
    // 채팅과 관련없는 패킷 구분 및 페이로드 오프셋 구하기
    if (!GetPayloadOffset(packet, packet_len, &packet_info)) return FAILURE;
    int loop_count = 0;
    while (true) { // 패킷에 있는 모든 레코드를 처리할때까지
        if (packet_info.packet_len < packet_info.payload_offset) { // 패킷을 다 읽음
            return SUCCESS;
        }
        // 다 담기면 초기화하고 continue 
        // 일부만 담기면 CASE1: len = DEFAULT_INT_VALUE하고 return CASE2: len 8이상 return
        // 패킷을 다 읽으면 return 
        if (global_record_buffer.len == DEFAULT_INT_VALUE && global_record_buffer.position == 0) { // 아무것도 안담긴 상태
            int a = packet_info.packet_len - packet_info.payload_offset + 1;
            if (packet_info.packet_len < packet_info.payload_offset + 8) { // record가 짤렸는데 길이 정보조차 안왔을때
                for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // 남은거 버퍼에 담기
                    global_record_buffer.buffer[i] = packet[i];
                }
                packet_info.payload_offset = packet_info.packet_len + 1; // 패킷 끝까지 다 읽음
                global_record_buffer.len = DEFAULT_INT_VALUE; // 길이 정보를 몰라 DEFAULT_INT_VALUE 초기화
                global_record_buffer.position = a; // 버퍼가 채워진 크기
                global_record_buffer.offset = 0;
                // 현재 레코드 처리는 다음 패킷에서
                return SUCCESS;
            }
            else {
                // GetRecordSize는 buffer가 채워저야 사용가능 해서 이 코드는 잘못됨
                // buffer.len은 버퍼가 다 채워져야 사용가능해서 이 코드는 잘못됨
                int r_size = GetRecordSize();
                if (global_record_buffer.len >= packet_info.payload_offset + r_size - 1) { // 패킷안에 레코드가 다 담겼을때
                    for (int i = packet_info.payload_offset; i < r_size; i++) { // 남은거 버퍼에 담기
                        global_record_buffer.buffer[i] = packet[i];
                    }
                    packet_info.payload_offset += r_size; // 패킷안의 현재 레코드 다 읽음
                    global_record_buffer.len = r_size;
                    global_record_buffer.position = global_record_buffer.len;
                    global_record_buffer.offset = 0;
                    if (IsRecord()) { // 완성된 레코드 파싱
                        // packet_len, payload_offset, nickname, chat, channel 구하기
                        if (IsChat()) { // 레코드 속성이 채팅인지 확인
                            ParseRecord(); // 레코드 파싱
                        }
                        else { // 채팅이 아니니 초기화 하고 새출발
                            RecordReset();
                            return FAILURE;
                        }
                    }
                    else { // 레코드가 아니니 초기화 하고 새출발
                        std::cout << "레코드가 아닙니다.\n";
                        RecordReset();
                        return FAILURE;
                    }
                    // 다음 레코드도 현재 패킷안에 들어있을수도 있으니
                    RecordReset();
                    continue;
                }
                else {// 레코드가 짤렸지만 길이 정보는 왔을때
                    int r_size = GetRecordSize();
                    a = packet_info.packet_len - packet_info.payload_offset + 1;
                    for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // 남은거 버퍼에 담기
                        global_record_buffer.buffer[i] = packet[i];
                    }
                    packet_info.payload_offset = packet_info.packet_len + 1; // 패킷 끝까지 다 읽음
                    global_record_buffer.len = r_size;
                    global_record_buffer.position = a; // 버퍼가 채워진 크기
                    global_record_buffer.offset = 0;
                    // 현재 레코드 처리는 다음 패킷에서
                    return SUCCESS;
                }
                std::cout << "WARRING여기 올 수가 없음1\n";
                return FAILURE;
            }
            // 정상 처리 완료
            return SUCCESS;
        }
        // 짤린 패킷이 다음 패킷에서 도착한 경우(이전 패킷에 길이정보 없을때)(이번 패킷에는 무조건 길이정보가 안짤렸을 경우를 가정)
        if (global_record_buffer.len == DEFAULT_INT_VALUE) { // 이전 패킷에 레코드 길이정보가 안담겨있을때 
            int r_size = GetRecordSize();
            if (global_record_buffer.len >= packet_info.payload_offset + r_size - 1) { // 패킷안에 레코드가 다 담겼을때
                for (int i = packet_info.payload_offset; i < r_size; i++) { // 남은거 버퍼에 담기
                    global_record_buffer.buffer[global_record_buffer.position + i] = packet[i];
                }
                packet_info.payload_offset += r_size; // 패킷안의 현재 레코드 다 읽음
                global_record_buffer.len = r_size;
                global_record_buffer.position = global_record_buffer.len;
                global_record_buffer.offset = 0;
                if (IsRecord()) { // 완성된 레코드 파싱
                    // packet_len, payload_offset, nickname, chat, channel 구하기
                    if (IsChat()) { // 레코드 속성이 채팅인지 확인
                        ParseRecord(); // 레코드 파싱
                    }
                    else { // 채팅이 아니니 초기화 하고 새출발
                        RecordReset();
                        return FAILURE;
                    }
                }
                else { // 레코드가 아니니 초기화 하고 새출발
                    std::cout << "레코드가 아닙니다.\n";
                    RecordReset();
                    return FAILURE;
                }
                // 다음 레코드도 현재 패킷안에 들어있을수도 있으니
                RecordReset();
                continue;
            }
            else {// 레코드가 또 짤림
                int a = packet_info.packet_len - packet_info.payload_offset + 1;
                for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // 남은거 버퍼에 담기
                    global_record_buffer.buffer[i] = packet[i];
                }
                packet_info.payload_offset = packet_info.packet_len + 1; // 패킷 끝까지 다 읽음
                global_record_buffer.len = r_size;
                global_record_buffer.position = a; // 버퍼가 채워진 크기
                global_record_buffer.offset = 0;
                // 현재 레코드 처리는 다음 패킷에서
                return SUCCESS;
            }
            std::cout << "WARRING여기 올 수가 없음2\n";
            return FAILURE;
        }

        if (global_record_buffer.len > 0 && (global_record_buffer.len > global_record_buffer.position)) {// 이전 패킷에 레코드 길이정보가 담겨있었을때
            int r_size = GetRecordSize();
            if (global_record_buffer.len >= packet_info.payload_offset + r_size - 1) { // 패킷안에 레코드가 다 담겼을때
                for (int i = packet_info.payload_offset; i < r_size; i++) { // 남은거 버퍼에 담기
                    global_record_buffer.buffer[global_record_buffer.position + i] = packet[i];
                }
                packet_info.payload_offset += r_size; // 패킷안의 현재 레코드 다 읽음
                // global_record_buffer.len = r_size;
                global_record_buffer.position = global_record_buffer.len;
                global_record_buffer.offset = 0;
                if (IsRecord()) { // 완성된 레코드 파싱
                    // packet_len, payload_offset, nickname, chat, channel 구하기
                    if (IsChat()) { // 레코드 속성이 채팅인지 확인
                        ParseRecord(); // 레코드 파싱
                    }
                    else { // 채팅이 아니니 초기화 하고 새출발
                        RecordReset();
                        return FAILURE;
                    }
                }
                else { // 레코드가 아니니 초기화 하고 새출발
                    std::cout << "레코드가 아닙니다.\n";
                    RecordReset();
                    return FAILURE;
                }
                // 다음 레코드도 현재 패킷안에 들어있을수도 있으니
                RecordReset();
                continue;
            }
            else {// 레코드가 또 짤림
                int a = packet_info.packet_len - packet_info.payload_offset + 1;
                for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // 남은거 버퍼에 담기
                    global_record_buffer.buffer[i] = packet[i];
                }
                packet_info.payload_offset = packet_info.packet_len + 1; // 패킷 끝까지 다 읽음
                // global_record_buffer.len = r_size;
                global_record_buffer.position = a; // 버퍼가 채워진 크기
                global_record_buffer.offset = 0;
                // 현재 레코드 처리는 다음 패킷에서
                return SUCCESS;
            }
            std::cout << "WARRING여기 올 수가 없음2\n";
            return FAILURE;
        }

        if (loop_count % 3 == 2) {
            std::cout << "무한루프중 횟수: " << loop_count << std::endl;
            if (loop_count > 10) {
                return FAILURE;
            }
        }
        loop_count += 1;
    }
}

int ParseRecord() {

    std::string type_name;
    const int TYPE = GetChatType();

    int nickname_len = 0;
    int chat_len = 0;

    // UTF-8 → 콘솔 인코딩 변환
    if (GetNickname(&nickname_len) == 0) return FAILURE;
    std::string nickname = UTF8ToConsoleEncoding(global_record_buffer.info->nickname, nickname_len);

    if (GetChatContent(&chat_len) == 0) return FAILURE;
    std::string chat_content = UTF8ToConsoleEncoding(global_record_buffer.info->chat_content, chat_len);

    // 알림 설정
    CheckKeywordTrigger(chat_content, TYPE);

    std::cout << "닉네임 길이: " << nickname_len << " 채팅 길이: " << chat_len << std::endl;
    // 표준 출력
    std::cout << type_name << " nickname: " << nickname << " 내용: " << chat_content << std::endl;

    return SUCCESS;
}


// RecordKeywordCheck <- 디버깅용
// offset은 tcp페이로드 시작점 + 이전 패킷에 다 담기지 못 한 record조각 길이
int RecordKeywordCheck(int offset, const u_char* packet, int packet_len) {
    // 디버깅 결과: tcp페이로드보다 레코드가 작을경우 레코드가 끝나면 그 다음 데이터도 레코드임
    // 로그 찍어보면 레코드가 패킷에 온전하게 담길 확률이 반반임
    // 비교할 4바이트 HEX 값(Record의 시작을 나타내는 코드)
    const u_char target[4] = { 0x54, 0x4F, 0x5A, 0x20 };

    // 패킷 데이터가 4바이트 이상 남아 있는지 확인 (범위 초과 방지)
    if (packet_len < offset + 4) {
        return 0; // 4바이트 이상 남아있지 않음
    }

    // packet[offset] ~ packet[offset+3] 비교
    for (int i = 0; i < 4; i++) {
        if (packet[offset + i] != target[i]) {
            // StartPattenCheck이 완성되면 로그 지우기
            // std::cout << "조각난 TCP페이로드 입니다." << std::endl;
            return 0; // 값이 다르면 0 반환
        }
    }
    // StartPattenCheck이 완성되면 로그 지우기
    // std::cout << "레코드시작점이 TCP페이로드 시작점과 같습니다." << std::endl;
    // 여기부터는 페이로드 첫부분이 레코드 시작일 경우임
    if (packet_len < offset + 25) {
        std::cout << "여긴 들을 가능성이 없음" << std::endl;
        return 0;
    }
    // 레코드길이 오프셋으로 이동
    offset += 4;
    int record_len = packet[offset] | (packet[offset + 1] << 8) |
        (packet[offset + 2] << 16) | (packet[offset + 3] << 24);
    if (packet_len == offset + 21 + record_len) {
        std::cout << "패킷 하나에 레코드 1개" << std::endl;
    }
    else if (packet_len < offset + 21 + record_len) {
        std::cout << "패킷 하나에 레코드 0.5개" << "패킷길이: " << packet_len << " 필요한 길이: " << offset + 21 + record_len << std::endl;
    }
    else {
        std::cout << "패킷 하나에 레코드 여러개" << "패킷길이: " << packet_len << " 필요한 길이: " << offset + 21 + record_len << std::endl;
        if (packet_len > offset + 21 + record_len + 4) {
            // 레코드 다음은 레코드일지 확인
            offset += 21 + record_len;
            int check_flag = 1;
            for (int i = 0; i < 4; i++) {
                if (packet[offset + i] != target[i]) {
                    check_flag = 0;
                }
            }
            if (check_flag) {
                std::cout << "2번째 레코드 시작" << std::endl;
            }
            else {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << "2번째 레코드가 아님" << std::endl;
                SetConsoleTextAttribute(hConsole, defaultColor);
            }
        }
        else {
            std::cout << "2번째 레코드의 식별자4바이트는 크기가 부족해 확인 불가" << std::endl;
        }
    }
    return SUCCESS;
}

void RecordReset() {
    global_record_buffer.len = 0;
    global_record_buffer.position = DEFAULT_INT_VALUE;
    global_record_buffer.offset = 0;
    global_info.ch = nullptr;
    global_info.chat_type = 0;
    global_info.chat_content = nullptr;
    global_info.nickname = nullptr;
    // global_record_buffer.buffer = r_buffer;
    // global_record_buffer.info = &global_info;
}

void CheckKeywordTrigger(const std::string& text, int TYPE) {
    // std 콘솔 출력 빨간 글씨로 변경
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);

    // if (text.find("어금니") != std::string::npos) { // "어금니"가 포함되어 있는지 확인
        // isTrigger = 1;
        // std::cout << "[!] 키워드 '어금니' 감지됨! 트리거 활성화\n";
    // }
    if (TYPE == 6) {
        isTrigger = 1; // 귓말 왔을때 소리 알림
    }
    // std 콘솔 출력 색깔 원상복구
    SetConsoleTextAttribute(hConsole, defaultColor);
}

int GetNickname(int* nickname_len) {
    int TYPE = global_record_buffer.info->chat_type;
    u_char* buffer = global_record_buffer.buffer;
    int* offset = &global_record_buffer.offset;
    if (TYPE == 1) {
        // entity 길이 오프셋 이동
        *offset += 6;
        // entity 길이(리틀 엔디안, 4바이트)
        int e_len = GetSize(buffer, *offset);
        if (e_len > MAX_ENTITY_LENGTH) return FAILURE;
        // entity 문자열 오프셋 이동
        *offset += 4;
        // EOT 오프셋 이동
        *offset += e_len;
        // 닉네임 길이 오프셋 이동
        *offset += 2;
        // 닉네임 길이(리틀 엔디안, 4바이트)
        *nickname_len = GetSize(buffer, *offset);
        if (*nickname_len > MAX_NAME_LENGTH) return FAILURE;
        // 닉네임 문자열 오프셋 이동
        *offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        global_record_buffer.info->nickname = buffer + *offset;
        // PrintHex(packet, *nickname_len, offset);
        *offset += *nickname_len;
        return SUCCESS;
    }
    else if (TYPE == 5) {
        return FAILURE;
        // entity 길이 오프셋 이동
        *offset += 6;
        // entity 길이(리틀 엔디안, 4바이트)
        int e_len = GetSize(buffer, *offset);
        if (e_len > MAX_ENTITY_LENGTH) return FAILURE;
        // entity 문자열 오프셋 이동
        *offset += 4;
        // EOT 오프셋 이동
        *offset += e_len;
        // 여기부터 닉네임과 채팅의 위치가 바뀜
    }
    else if (TYPE == 3 or TYPE == 4 or TYPE == 6) {
        // 닉네임 길이 오프셋 이동
        *offset += 6;
        // 닉네임 길이(리틀 엔디안, 4바이트)
        *nickname_len = GetSize(buffer, *offset);
        if (*nickname_len > MAX_NAME_LENGTH) return FAILURE;
        // 닉네임 문자열 오프셋 이동
        *offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        global_record_buffer.info->nickname = buffer + *offset;
        // PrintHex(packet, *nickname_len, offset);
        *offset += *nickname_len;
        return SUCCESS;
    }
    else {
        return FAILURE;
    }
}

int GetChatContent(int* chat_len) {
    int TYPE = global_record_buffer.info->chat_type;
    u_char* buffer = global_record_buffer.buffer;
    int* offset = &global_record_buffer.offset;
    if (TYPE == 4 or TYPE == 1) {
        // 채팅 길이 오프셋 이동
        *offset += 2;
        // 채팅 길이(리틀 엔디안, 4바이트)
        *chat_len = GetSize(buffer, *offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // 채팅 문자열 오프셋 이동
        *offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        global_record_buffer.info->chat_content = buffer + *offset;
        *offset += *chat_len;
        return SUCCESS;
    }
    else if (TYPE == 3) {
        // 채팅 길이 오프셋 이동
        *offset += 2;
        // 채팅 길이(리틀 엔디안, 4바이트)
        *chat_len = GetSize(buffer, *offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // 채팅 문자열 오프셋 이동
        *offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        global_record_buffer.info->chat_content = buffer + *offset;
        *offset += *chat_len;
        return SUCCESS;
    }
    else if (TYPE == 5) {
        return 0;
        // 채팅과 닉네임의 위치가 바뀜
    }
    else if (TYPE == 6) {
        // 채널 길이 오프셋 이동
        *offset += 2;
        // 채널 길이 오프셋 이동(리틀 엔디안, 4바이트)
        int c_len = GetSize(buffer, *offset);
        if (c_len > MAX_CHANNEL_LENGTH) return 0;
        // 채널 문자열 오프셋 이동
        *offset += 4;
        // EOT 오프셋 이동
        *offset += c_len;
        // 채팅 길이 오프셋 이동
        *offset += 2;
        // 채팅 길이(리틀 엔디안, 4바이트)
        *chat_len = GetSize(buffer, *offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // 채팅 문자열 이동
        *offset += 4;
        // 원본 패킷 데이터를 직접 참조 (복사하지 않음)
        global_record_buffer.info->chat_content = buffer + *offset;
        *offset += *chat_len;
        return SUCCESS;
    }
    else {
        return 0;
    }
}

int GetChatType() {
    int num_patterns = sizeof(patterns) / sizeof(patterns[0]);
    for (int i = 0; i < num_patterns; i++) {
        if (memcmp(global_record_buffer.buffer + global_record_buffer.offset, patterns[i].pattern, 5) == 0) {
            global_record_buffer.offset += 5;
            global_record_buffer.info->chat_type = patterns[i].type;
            std::cout << "채팅 종류는 " << patterns[i].name << " 입니다." << std::endl;
            return patterns[i].type;
        }
    }

    std::cout << "채팅 종류는 알 수 없음 입니다." << std::endl;
    return FAILURE;
}

int IsChat()
{
    //global_record_buffer.offset += 14; 
    if (memcmp(global_record_buffer.buffer + 17, chatPattern, sizeof(chatPattern)) == 0) {
        std::cout << "-------------------" << std::endl;
        std::cout << "채팅 패턴이 오프셋" << 17 << "에서 발견되었습니다." << std::endl;
        global_record_buffer.offset += sizeof(chatPattern) + 17;
        return SUCCESS;
    }
    else {
        global_record_buffer.offset += sizeof(chatPattern) + 17;
        std::cout << "알수 없는 바이트 패턴입니다." << std::endl;
        return FAILURE;
    }
}

// little-endian 4바이트 길이 구하기
int GetSize(u_char* packet, int offset) {
    int size = packet[offset] | (packet[offset + 1] << 8) |
        (packet[offset + 2] << 16) | (packet[offset + 3] << 24);
    return size;
}

int GetRecordSize() {
    //global_record_buffer.offset += 4;
    int size = GetSize(global_record_buffer.buffer, 4) + 25; // 25번째 오프셋부터 길이안에 포함됨
    std::cout << "레코드 사이즈: " << size << std::endl;
    return size;
}

int IsRecord() {
    if (memcmp(global_record_buffer.buffer, recordPattern, sizeof(recordPattern)) == 0) {
        //global_record_buffer.offset += 4;
        std::cout << "레코드O " << std::endl;
        return SUCCESS;
    }
    std::cout << "레코드X " << std::endl;
    //PrintHex(global_record_buffer.buffer, 4);
    return FAILURE;
}

int GetPayloadOffset(const u_char* packet, int packet_len, struct packet_info* packet_info)
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
    if (utf8_str_b == nullptr || length == 0) return ""; // NULL 체크 및 빈 문자열 처리

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