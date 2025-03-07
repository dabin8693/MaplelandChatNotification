#include "packet_parser.h"
#include <iomanip>  // std::hex, std::setw, std::setfill
// --- [ ���� ���� ���� ] ---
const unsigned char recordPattern[] = { 0x54, 0x4f, 0x5a, 0x20 };
const unsigned char chatPattern[] = { 0x98, 0xac, 0x25, 0xcf, 0xff, 0xff, 0xff, 0xff, 0x00, 0x98, 0xac, 0x25, 0xcf, 0x01, 0x00, 0x00, 0x00,
0x71, 0x00, 0x00, 0x80 }; // 21 ����Ʈ
const unsigned char allChat[] = { 0x02, 0x00, 0x00, 0x00, 0x00 };
const unsigned char petChat_send[] = { 0x10, 0x00, 0x00, 0x00, 0x00 };
const unsigned char sameChat_receive[] = { 0x04, 0x00, 0x00, 0x00, 0x00 };
const unsigned char cashChat_receive[] = { 0x05, 0x00, 0x00, 0x00, 0x00 };
const unsigned char privateChat_send[] = { 0x0c, 0x00, 0x00, 0x00, 0x00 };
const unsigned char privateChat_receive[] = { 0x0d, 0x00, 0x00, 0x00, 0x00 };
// �������� ���� �� �ʱ�ȭ
const struct {
    const unsigned char* pattern;
    int type;
    const char* name;
} patterns[] = {
    { allChat, 1, "��ü ä��"},
    { petChat_send, 2, "�� ä��(��Ȯ���� �� ��)"},
    { sameChat_receive, 3, "ä�� ä��"},
    { cashChat_receive, 4, "��Ȯ"},
    { privateChat_send, 5, "�ӼӸ�(�۽�)"},
    { privateChat_receive, 6, "�ӼӸ�(����)"}
};

struct record_buffer global_record_buffer = {
    nullptr, DEFAULT_INT_VALUE, 0, 0,nullptr
};

struct info global_info = {
    nullptr, nullptr, DEFAULT_INT_VALUE
};

int ParsePacket(const u_char* packet, int packet_len) {
    // ��Ŷ���� ����ü�� ���������� ����
    packet_info packet_info = { 0, 0 };
    // ä�ð� ���þ��� ��Ŷ ���� �� ���̷ε� ������ ���ϱ�
    if (!GetPayloadOffset(packet, packet_len, &packet_info)) return FAILURE;
    int loop_count = 0;
    while (true) { // ��Ŷ�� �ִ� ��� ���ڵ带 ó���Ҷ�����
        if (packet_info.packet_len < packet_info.payload_offset) { // ��Ŷ�� �� ����
            return SUCCESS;
        }
        // �� ���� �ʱ�ȭ�ϰ� continue 
        // �Ϻθ� ���� CASE1: len = DEFAULT_INT_VALUE�ϰ� return CASE2: len 8�̻� return
        // ��Ŷ�� �� ������ return 
        if (global_record_buffer.len == DEFAULT_INT_VALUE && global_record_buffer.position == 0) { // �ƹ��͵� �ȴ�� ����
            int a = packet_info.packet_len - packet_info.payload_offset + 1;
            if (packet_info.packet_len < packet_info.payload_offset + 8) { // record�� ©�ȴµ� ���� �������� �ȿ�����
                for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // ������ ���ۿ� ���
                    global_record_buffer.buffer[i] = packet[i];
                }
                packet_info.payload_offset = packet_info.packet_len + 1; // ��Ŷ ������ �� ����
                global_record_buffer.len = DEFAULT_INT_VALUE; // ���� ������ ���� DEFAULT_INT_VALUE �ʱ�ȭ
                global_record_buffer.position = a; // ���۰� ä���� ũ��
                global_record_buffer.offset = 0;
                // ���� ���ڵ� ó���� ���� ��Ŷ����
                return SUCCESS;
            }
            else {
                // GetRecordSize�� buffer�� ä������ ��밡�� �ؼ� �� �ڵ�� �߸���
                // buffer.len�� ���۰� �� ä������ ��밡���ؼ� �� �ڵ�� �߸���
                int r_size = GetRecordSize();
                if (global_record_buffer.len >= packet_info.payload_offset + r_size - 1) { // ��Ŷ�ȿ� ���ڵ尡 �� �������
                    for (int i = packet_info.payload_offset; i < r_size; i++) { // ������ ���ۿ� ���
                        global_record_buffer.buffer[i] = packet[i];
                    }
                    packet_info.payload_offset += r_size; // ��Ŷ���� ���� ���ڵ� �� ����
                    global_record_buffer.len = r_size;
                    global_record_buffer.position = global_record_buffer.len;
                    global_record_buffer.offset = 0;
                    if (IsRecord()) { // �ϼ��� ���ڵ� �Ľ�
                        // packet_len, payload_offset, nickname, chat, channel ���ϱ�
                        if (IsChat()) { // ���ڵ� �Ӽ��� ä������ Ȯ��
                            ParseRecord(); // ���ڵ� �Ľ�
                        }
                        else { // ä���� �ƴϴ� �ʱ�ȭ �ϰ� �����
                            RecordReset();
                            return FAILURE;
                        }
                    }
                    else { // ���ڵ尡 �ƴϴ� �ʱ�ȭ �ϰ� �����
                        std::cout << "���ڵ尡 �ƴմϴ�.\n";
                        RecordReset();
                        return FAILURE;
                    }
                    // ���� ���ڵ嵵 ���� ��Ŷ�ȿ� ����������� ������
                    RecordReset();
                    continue;
                }
                else {// ���ڵ尡 ©������ ���� ������ ������
                    int r_size = GetRecordSize();
                    a = packet_info.packet_len - packet_info.payload_offset + 1;
                    for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // ������ ���ۿ� ���
                        global_record_buffer.buffer[i] = packet[i];
                    }
                    packet_info.payload_offset = packet_info.packet_len + 1; // ��Ŷ ������ �� ����
                    global_record_buffer.len = r_size;
                    global_record_buffer.position = a; // ���۰� ä���� ũ��
                    global_record_buffer.offset = 0;
                    // ���� ���ڵ� ó���� ���� ��Ŷ����
                    return SUCCESS;
                }
                std::cout << "WARRING���� �� ���� ����1\n";
                return FAILURE;
            }
            // ���� ó�� �Ϸ�
            return SUCCESS;
        }
        // ©�� ��Ŷ�� ���� ��Ŷ���� ������ ���(���� ��Ŷ�� �������� ������)(�̹� ��Ŷ���� ������ ���������� ��©���� ��츦 ����)
        if (global_record_buffer.len == DEFAULT_INT_VALUE) { // ���� ��Ŷ�� ���ڵ� ���������� �ȴ�������� 
            int r_size = GetRecordSize();
            if (global_record_buffer.len >= packet_info.payload_offset + r_size - 1) { // ��Ŷ�ȿ� ���ڵ尡 �� �������
                for (int i = packet_info.payload_offset; i < r_size; i++) { // ������ ���ۿ� ���
                    global_record_buffer.buffer[global_record_buffer.position + i] = packet[i];
                }
                packet_info.payload_offset += r_size; // ��Ŷ���� ���� ���ڵ� �� ����
                global_record_buffer.len = r_size;
                global_record_buffer.position = global_record_buffer.len;
                global_record_buffer.offset = 0;
                if (IsRecord()) { // �ϼ��� ���ڵ� �Ľ�
                    // packet_len, payload_offset, nickname, chat, channel ���ϱ�
                    if (IsChat()) { // ���ڵ� �Ӽ��� ä������ Ȯ��
                        ParseRecord(); // ���ڵ� �Ľ�
                    }
                    else { // ä���� �ƴϴ� �ʱ�ȭ �ϰ� �����
                        RecordReset();
                        return FAILURE;
                    }
                }
                else { // ���ڵ尡 �ƴϴ� �ʱ�ȭ �ϰ� �����
                    std::cout << "���ڵ尡 �ƴմϴ�.\n";
                    RecordReset();
                    return FAILURE;
                }
                // ���� ���ڵ嵵 ���� ��Ŷ�ȿ� ����������� ������
                RecordReset();
                continue;
            }
            else {// ���ڵ尡 �� ©��
                int a = packet_info.packet_len - packet_info.payload_offset + 1;
                for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // ������ ���ۿ� ���
                    global_record_buffer.buffer[i] = packet[i];
                }
                packet_info.payload_offset = packet_info.packet_len + 1; // ��Ŷ ������ �� ����
                global_record_buffer.len = r_size;
                global_record_buffer.position = a; // ���۰� ä���� ũ��
                global_record_buffer.offset = 0;
                // ���� ���ڵ� ó���� ���� ��Ŷ����
                return SUCCESS;
            }
            std::cout << "WARRING���� �� ���� ����2\n";
            return FAILURE;
        }

        if (global_record_buffer.len > 0 && (global_record_buffer.len > global_record_buffer.position)) {// ���� ��Ŷ�� ���ڵ� ���������� ����־�����
            int r_size = GetRecordSize();
            if (global_record_buffer.len >= packet_info.payload_offset + r_size - 1) { // ��Ŷ�ȿ� ���ڵ尡 �� �������
                for (int i = packet_info.payload_offset; i < r_size; i++) { // ������ ���ۿ� ���
                    global_record_buffer.buffer[global_record_buffer.position + i] = packet[i];
                }
                packet_info.payload_offset += r_size; // ��Ŷ���� ���� ���ڵ� �� ����
                // global_record_buffer.len = r_size;
                global_record_buffer.position = global_record_buffer.len;
                global_record_buffer.offset = 0;
                if (IsRecord()) { // �ϼ��� ���ڵ� �Ľ�
                    // packet_len, payload_offset, nickname, chat, channel ���ϱ�
                    if (IsChat()) { // ���ڵ� �Ӽ��� ä������ Ȯ��
                        ParseRecord(); // ���ڵ� �Ľ�
                    }
                    else { // ä���� �ƴϴ� �ʱ�ȭ �ϰ� �����
                        RecordReset();
                        return FAILURE;
                    }
                }
                else { // ���ڵ尡 �ƴϴ� �ʱ�ȭ �ϰ� �����
                    std::cout << "���ڵ尡 �ƴմϴ�.\n";
                    RecordReset();
                    return FAILURE;
                }
                // ���� ���ڵ嵵 ���� ��Ŷ�ȿ� ����������� ������
                RecordReset();
                continue;
            }
            else {// ���ڵ尡 �� ©��
                int a = packet_info.packet_len - packet_info.payload_offset + 1;
                for (int i = packet_info.payload_offset; i < packet_info.packet_len + 1; i++) { // ������ ���ۿ� ���
                    global_record_buffer.buffer[i] = packet[i];
                }
                packet_info.payload_offset = packet_info.packet_len + 1; // ��Ŷ ������ �� ����
                // global_record_buffer.len = r_size;
                global_record_buffer.position = a; // ���۰� ä���� ũ��
                global_record_buffer.offset = 0;
                // ���� ���ڵ� ó���� ���� ��Ŷ����
                return SUCCESS;
            }
            std::cout << "WARRING���� �� ���� ����2\n";
            return FAILURE;
        }

        if (loop_count % 3 == 2) {
            std::cout << "���ѷ����� Ƚ��: " << loop_count << std::endl;
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

    // UTF-8 �� �ܼ� ���ڵ� ��ȯ
    if (GetNickname(&nickname_len) == 0) return FAILURE;
    std::string nickname = UTF8ToConsoleEncoding(global_record_buffer.info->nickname, nickname_len);

    if (GetChatContent(&chat_len) == 0) return FAILURE;
    std::string chat_content = UTF8ToConsoleEncoding(global_record_buffer.info->chat_content, chat_len);

    // �˸� ����
    CheckKeywordTrigger(chat_content, TYPE);

    std::cout << "�г��� ����: " << nickname_len << " ä�� ����: " << chat_len << std::endl;
    // ǥ�� ���
    std::cout << type_name << " nickname: " << nickname << " ����: " << chat_content << std::endl;

    return SUCCESS;
}


// RecordKeywordCheck <- ������
// offset�� tcp���̷ε� ������ + ���� ��Ŷ�� �� ����� �� �� record���� ����
int RecordKeywordCheck(int offset, const u_char* packet, int packet_len) {
    // ����� ���: tcp���̷ε庸�� ���ڵ尡 ������� ���ڵ尡 ������ �� ���� �����͵� ���ڵ���
    // �α� ���� ���ڵ尡 ��Ŷ�� �����ϰ� ��� Ȯ���� �ݹ���
    // ���� 4����Ʈ HEX ��(Record�� ������ ��Ÿ���� �ڵ�)
    const u_char target[4] = { 0x54, 0x4F, 0x5A, 0x20 };

    // ��Ŷ �����Ͱ� 4����Ʈ �̻� ���� �ִ��� Ȯ�� (���� �ʰ� ����)
    if (packet_len < offset + 4) {
        return 0; // 4����Ʈ �̻� �������� ����
    }

    // packet[offset] ~ packet[offset+3] ��
    for (int i = 0; i < 4; i++) {
        if (packet[offset + i] != target[i]) {
            // StartPattenCheck�� �ϼ��Ǹ� �α� �����
            // std::cout << "������ TCP���̷ε� �Դϴ�." << std::endl;
            return 0; // ���� �ٸ��� 0 ��ȯ
        }
    }
    // StartPattenCheck�� �ϼ��Ǹ� �α� �����
    // std::cout << "���ڵ�������� TCP���̷ε� �������� �����ϴ�." << std::endl;
    // ������ʹ� ���̷ε� ù�κ��� ���ڵ� ������ �����
    if (packet_len < offset + 25) {
        std::cout << "���� ���� ���ɼ��� ����" << std::endl;
        return 0;
    }
    // ���ڵ���� ���������� �̵�
    offset += 4;
    int record_len = packet[offset] | (packet[offset + 1] << 8) |
        (packet[offset + 2] << 16) | (packet[offset + 3] << 24);
    if (packet_len == offset + 21 + record_len) {
        std::cout << "��Ŷ �ϳ��� ���ڵ� 1��" << std::endl;
    }
    else if (packet_len < offset + 21 + record_len) {
        std::cout << "��Ŷ �ϳ��� ���ڵ� 0.5��" << "��Ŷ����: " << packet_len << " �ʿ��� ����: " << offset + 21 + record_len << std::endl;
    }
    else {
        std::cout << "��Ŷ �ϳ��� ���ڵ� ������" << "��Ŷ����: " << packet_len << " �ʿ��� ����: " << offset + 21 + record_len << std::endl;
        if (packet_len > offset + 21 + record_len + 4) {
            // ���ڵ� ������ ���ڵ����� Ȯ��
            offset += 21 + record_len;
            int check_flag = 1;
            for (int i = 0; i < 4; i++) {
                if (packet[offset + i] != target[i]) {
                    check_flag = 0;
                }
            }
            if (check_flag) {
                std::cout << "2��° ���ڵ� ����" << std::endl;
            }
            else {
                SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << "2��° ���ڵ尡 �ƴ�" << std::endl;
                SetConsoleTextAttribute(hConsole, defaultColor);
            }
        }
        else {
            std::cout << "2��° ���ڵ��� �ĺ���4����Ʈ�� ũ�Ⱑ ������ Ȯ�� �Ұ�" << std::endl;
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
    // std �ܼ� ��� ���� �۾��� ����
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);

    // if (text.find("��ݴ�") != std::string::npos) { // "��ݴ�"�� ���ԵǾ� �ִ��� Ȯ��
        // isTrigger = 1;
        // std::cout << "[!] Ű���� '��ݴ�' ������! Ʈ���� Ȱ��ȭ\n";
    // }
    if (TYPE == 6) {
        isTrigger = 1; // �Ӹ� ������ �Ҹ� �˸�
    }
    // std �ܼ� ��� ���� ���󺹱�
    SetConsoleTextAttribute(hConsole, defaultColor);
}

int GetNickname(int* nickname_len) {
    int TYPE = global_record_buffer.info->chat_type;
    u_char* buffer = global_record_buffer.buffer;
    int* offset = &global_record_buffer.offset;
    if (TYPE == 1) {
        // entity ���� ������ �̵�
        *offset += 6;
        // entity ����(��Ʋ �����, 4����Ʈ)
        int e_len = GetSize(buffer, *offset);
        if (e_len > MAX_ENTITY_LENGTH) return FAILURE;
        // entity ���ڿ� ������ �̵�
        *offset += 4;
        // EOT ������ �̵�
        *offset += e_len;
        // �г��� ���� ������ �̵�
        *offset += 2;
        // �г��� ����(��Ʋ �����, 4����Ʈ)
        *nickname_len = GetSize(buffer, *offset);
        if (*nickname_len > MAX_NAME_LENGTH) return FAILURE;
        // �г��� ���ڿ� ������ �̵�
        *offset += 4;
        // ���� ��Ŷ �����͸� ���� ���� (�������� ����)
        global_record_buffer.info->nickname = buffer + *offset;
        // PrintHex(packet, *nickname_len, offset);
        *offset += *nickname_len;
        return SUCCESS;
    }
    else if (TYPE == 5) {
        return FAILURE;
        // entity ���� ������ �̵�
        *offset += 6;
        // entity ����(��Ʋ �����, 4����Ʈ)
        int e_len = GetSize(buffer, *offset);
        if (e_len > MAX_ENTITY_LENGTH) return FAILURE;
        // entity ���ڿ� ������ �̵�
        *offset += 4;
        // EOT ������ �̵�
        *offset += e_len;
        // ������� �г��Ӱ� ä���� ��ġ�� �ٲ�
    }
    else if (TYPE == 3 or TYPE == 4 or TYPE == 6) {
        // �г��� ���� ������ �̵�
        *offset += 6;
        // �г��� ����(��Ʋ �����, 4����Ʈ)
        *nickname_len = GetSize(buffer, *offset);
        if (*nickname_len > MAX_NAME_LENGTH) return FAILURE;
        // �г��� ���ڿ� ������ �̵�
        *offset += 4;
        // ���� ��Ŷ �����͸� ���� ���� (�������� ����)
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
        // ä�� ���� ������ �̵�
        *offset += 2;
        // ä�� ����(��Ʋ �����, 4����Ʈ)
        *chat_len = GetSize(buffer, *offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // ä�� ���ڿ� ������ �̵�
        *offset += 4;
        // ���� ��Ŷ �����͸� ���� ���� (�������� ����)
        global_record_buffer.info->chat_content = buffer + *offset;
        *offset += *chat_len;
        return SUCCESS;
    }
    else if (TYPE == 3) {
        // ä�� ���� ������ �̵�
        *offset += 2;
        // ä�� ����(��Ʋ �����, 4����Ʈ)
        *chat_len = GetSize(buffer, *offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // ä�� ���ڿ� ������ �̵�
        *offset += 4;
        // ���� ��Ŷ �����͸� ���� ���� (�������� ����)
        global_record_buffer.info->chat_content = buffer + *offset;
        *offset += *chat_len;
        return SUCCESS;
    }
    else if (TYPE == 5) {
        return 0;
        // ä�ð� �г����� ��ġ�� �ٲ�
    }
    else if (TYPE == 6) {
        // ä�� ���� ������ �̵�
        *offset += 2;
        // ä�� ���� ������ �̵�(��Ʋ �����, 4����Ʈ)
        int c_len = GetSize(buffer, *offset);
        if (c_len > MAX_CHANNEL_LENGTH) return 0;
        // ä�� ���ڿ� ������ �̵�
        *offset += 4;
        // EOT ������ �̵�
        *offset += c_len;
        // ä�� ���� ������ �̵�
        *offset += 2;
        // ä�� ����(��Ʋ �����, 4����Ʈ)
        *chat_len = GetSize(buffer, *offset);
        if (*chat_len > MAX_CHAT_LENGTH) return 0;
        // ä�� ���ڿ� �̵�
        *offset += 4;
        // ���� ��Ŷ �����͸� ���� ���� (�������� ����)
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
            std::cout << "ä�� ������ " << patterns[i].name << " �Դϴ�." << std::endl;
            return patterns[i].type;
        }
    }

    std::cout << "ä�� ������ �� �� ���� �Դϴ�." << std::endl;
    return FAILURE;
}

int IsChat()
{
    //global_record_buffer.offset += 14; 
    if (memcmp(global_record_buffer.buffer + 17, chatPattern, sizeof(chatPattern)) == 0) {
        std::cout << "-------------------" << std::endl;
        std::cout << "ä�� ������ ������" << 17 << "���� �߰ߵǾ����ϴ�." << std::endl;
        global_record_buffer.offset += sizeof(chatPattern) + 17;
        return SUCCESS;
    }
    else {
        global_record_buffer.offset += sizeof(chatPattern) + 17;
        std::cout << "�˼� ���� ����Ʈ �����Դϴ�." << std::endl;
        return FAILURE;
    }
}

// little-endian 4����Ʈ ���� ���ϱ�
int GetSize(u_char* packet, int offset) {
    int size = packet[offset] | (packet[offset + 1] << 8) |
        (packet[offset + 2] << 16) | (packet[offset + 3] << 24);
    return size;
}

int GetRecordSize() {
    //global_record_buffer.offset += 4;
    int size = GetSize(global_record_buffer.buffer, 4) + 25; // 25��° �����º��� ���̾ȿ� ���Ե�
    std::cout << "���ڵ� ������: " << size << std::endl;
    return size;
}

int IsRecord() {
    if (memcmp(global_record_buffer.buffer, recordPattern, sizeof(recordPattern)) == 0) {
        //global_record_buffer.offset += 4;
        std::cout << "���ڵ�O " << std::endl;
        return SUCCESS;
    }
    std::cout << "���ڵ�X " << std::endl;
    //PrintHex(global_record_buffer.buffer, 4);
    return FAILURE;
}

int GetPayloadOffset(const u_char* packet, int packet_len, struct packet_info* packet_info)
{
    const int ethernet_header_length = 14;
    if (packet_len < ethernet_header_length) return FAILURE;

    const struct ether_header* eth_hdr = (const struct ether_header*)packet;
    // IPv6�� ���� ����Ŭ�� �Ѿ
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return FAILURE;

    const struct ip_header* ip_hdr = (const struct ip_header*)(packet + ethernet_header_length);
    int ip_header_length = (ip_hdr->version_ihl & 0x0F) * 4;

    if (packet_len < ethernet_header_length + ip_header_length) return FAILURE;
    // IPv6�� ���� ����Ŭ�� �Ѿ
    if (ip_hdr->protocol != IPPROTO_TCP) return FAILURE;

    uint16_t mf_bit = (ntohs(ip_hdr->flags_offset) & 0x2000) >> 13; // MF ��Ʈ ����
    uint16_t fragment_offset = (ntohs(ip_hdr->flags_offset) & 0x1FFF); // Fragment Offset ����
    // MF bit �� 1�̸� ���� ��Ŷ�̹Ƿ� ���� ����Ŭ�� �Ѿ(���� ���ҽ� �����͸� ���ҵǾ ��)(ä����Ŷ �м����� �ʿ�x)
    if (mf_bit) {
        std::cout << "ip��Ŷ�� ���������ϴ�." << std::endl;
        return FAILURE;
    }
    else {
        // ���ҵ� ��Ŷ�� ������ ��Ŷ�̹Ƿ� ���� ����Ŭ�� �Ѿ
        if (fragment_offset) {
            std::cout << "������ ip��Ŷ�� ������ �����Դϴ�. ���� ��ȣ : " << fragment_offset << std::endl;
            return FAILURE;
        }
    }
    // IPv4 ��Ŷ ũ�� ����
    uint16_t ip_total_length = ntohs(ip_hdr->total_length);

    const struct tcp_header* tcp_hdr = (const struct tcp_header*)(packet + ethernet_header_length + ip_header_length);
    // ������ ������ 4��Ʈ�� Ȯ���ؼ� ���� tcp����� ũ�� ���ϱ�
    int tcp_header_length = ((tcp_hdr->offset_reserved >> 4) & 0x0F) * 4;

    packet_info->payload_offset = ethernet_header_length + ip_header_length + tcp_header_length;
    packet_info->packet_len = packet_len;
    return packet_info->payload_offset;
}

// --- [ UTF-8 �� �ܼ� �⺻ ���ڵ�(CP949 ��) ��ȯ �Լ� ] ---
std::string UTF8ToConsoleEncoding(const u_char* utf8_str_b, size_t length) {
    if (utf8_str_b == nullptr || length == 0) return ""; // NULL üũ �� �� ���ڿ� ó��

    // UTF-8 �� UTF-16 ��ȯ
    int wlen = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(utf8_str_b), static_cast<int>(length), NULL, 0);
    if (wlen == 0) return "";

    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(utf8_str_b), static_cast<int>(length), &wstr[0], wlen);

    // UTF-16 �� �ܼ� �⺻ ���ڵ� ��ȯ (CP949 ��)
    int mblen = WideCharToMultiByte(GetConsoleOutputCP(), 0, wstr.c_str(), wlen, NULL, 0, NULL, NULL);
    if (mblen == 0) return "";

    std::string console_str(mblen, 0);
    WideCharToMultiByte(GetConsoleOutputCP(), 0, wstr.c_str(), wlen, &console_str[0], mblen, NULL, NULL);

    return console_str;
}

void PrintHex(const u_char* buffer, int length) {
    std::cout << "���� ����� �� ����: " << length << std::endl;
    for (int i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
    }
    std::cout << std::dec << std::endl;  // 10���� ������� ����
}