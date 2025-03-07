#include "packet_parser.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>

#define KEYWORDS_FILE "keywords.txt"

bool whisper_alert = false; // �Ӹ� �˸� �⺻�� off
bool whisper_set = false;   // �ߺ� ������

std::vector<Keyword> keywords; // ���� Ű���� ����Ʈ

void ParseKeywords(HANDLE hFile, std::ifstream* file, std::vector<Keyword>& keywords);
void PrintKeywords(const std::vector<Keyword>& keywords);
void CreateDefaultKeywordFile();

void LoadKeywords() {
    std::ifstream file(KEYWORDS_FILE, std::ios::in);
    if (!file) {
        std::cout << "Ű���� ������ �������� �ʽ��ϴ�. ���� �����մϴ�...\n";
        CreateDefaultKeywordFile();
        file.open(KEYWORDS_FILE, std::ios::in); // ���� �ٽ� ����
        if (!file) {
            std::cerr << "���� ���� ����!\n";
            return;
        }
    }

    // ���� ��� ���� (���� ����)
    HANDLE hFile = CreateFileA(KEYWORDS_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "���� ��� ����.\n";
        return;
    }

    // �ùٸ��� ���� ����
    ParseKeywords(hFile, &file, keywords);

    // Ű���� ��� �Լ� ȣ��
    PrintKeywords(keywords);
}

void ParseKeywords(HANDLE hFile, std::ifstream* file, std::vector<Keyword>& keywords) {
    std::string line;
    std::vector<bool> comment_stack;  // ������ �̿��� �ּ� ����

    while (std::getline(*file, line)) {
        size_t pos = 0;

        // ���� ������� �ּ� ó��
        while ((pos = line.find("/*", pos)) != std::string::npos) {
            comment_stack.push_back(true); // `/*` �߰� �� Ǫ��
            pos += 2;
        }
        pos = 0;
        while ((pos = line.find("*/", pos)) != std::string::npos) {
            if (!comment_stack.empty()) {
                comment_stack.pop_back(); // `*/` �߰� �� ��
            }
            pos += 2;
        }

        if (!comment_stack.empty()) continue; // �ּ� ���δ� ����

        // �Ӹ�(����) �˸� ���� ���� (�ߺ� ����)
        if (!whisper_set) {
            if (line.find("&{seton()}") != std::string::npos) {
                whisper_alert = true;
                whisper_set = true; // �ߺ� ���� ����
            }
            if (line.find("&{setoff()}") != std::string::npos) {
                whisper_alert = false;
                whisper_set = true; // �ߺ� ���� ����
            }
        }

        // Ű���� �Ľ� (`${Ÿ��,Ű����}` ����)
        pos = 0;
        while ((pos = line.find("${", pos)) != std::string::npos) {
            size_t end_pos = line.find("}", pos);
            if (end_pos == std::string::npos) break; // �ݴ� `}`�� ������ ����

            std::string token = line.substr(pos + 2, end_pos - pos - 2); // `${}` ���� ����
            size_t comma_pos = token.find(",");
            if (comma_pos != std::string::npos) {
                int type = std::stoi(token.substr(0, comma_pos)); // Ÿ�� ����
                std::string word = token.substr(comma_pos + 1); // Ű���� ����
                keywords.push_back({ type, word });
            }
            pos = end_pos + 1;
        }
    }

    file->close();
    CloseHandle(hFile);
}

// Ű���� ��� �Լ�
void PrintKeywords(const std::vector<Keyword>& keywords) {
    std::cout << "�Ӹ�(����) �˸�: " << (whisper_alert ? "ON" : "OFF") << std::endl;
    for (const auto& kw : keywords) {
        std::cout << "Ÿ��: " << kw.type << ", Ű����: " << kw.word << std::endl;
    }
}

void CreateDefaultKeywordFile() {
    std::ofstream file(KEYWORDS_FILE);
    if (file) {
        file << "/* �ּ��Դϴ�.\n"
            << "Ű���������ۼ� ��Ģ�Դϴ�.\n"
            << "��ϵ� Ű����� �Ҹ� �˸��� ���ɴϴ�.\n"
            << "1. Ű���� ������ ${Ÿ��,Ű����}\n"
            << "2. �ּ� ������ /*  */\n"
            << "3. Ÿ�� ������\n"
            << "Ÿ��0 = ��� ä��(��ê, ��Ȯ, �Ӹ� ��������)\n"
            << "Ÿ��1 = ��ü ä��\n"
            << "Ÿ��2 = �� ä��?(��Ȯ���� �� ��) <- ���� �ϼ��ȵ�\n"
            << "Ÿ��3 = ä�� ä��\n"
            << "Ÿ��4 = ��Ȯ\n"
            << "Ÿ��5 = �Ӹ�(�۽�) <- ���� �ϼ��ȵ�\n"
            << "Ÿ��6 = �Ӹ�(����)\n\n"
            << "4. �Ӹ�(����) �˸����� ���(�ΰ��� �ϳ��� ����)\n"
            << "&{setoff()} = �Ӹ�(����) �Ҹ��˸� ����\n"
            << "&{seton()} = �Ӹ�(����) �Ҹ��˸� �ѱ�\n"
            << "�Ӹ�(����)�˸��� �⺻������ off�� �Ǿ��ֽ��ϴ�.\n"
            << "on�����Ǹ� Ű����� ������� �Ӹ�(����)�� ��� �Ҹ� �˸��� ���ɴϴ�.\n"
            << "---------------------����---------------------\n"
            << "&{seton()}${3,��ݴ�}${4,Ȯ��}${1,�ڸ�}\n\n"
            << "*/ �ּ��� ���Դϴ�.\n";
        file.close();
        std::cout << "�⺻ Ű���� ������ �����Ǿ����ϴ�.\n";
    }
    else {
        std::cerr << "Ű���� ������ �����ϴ� �� �����߽��ϴ�!\n";
    }
}
