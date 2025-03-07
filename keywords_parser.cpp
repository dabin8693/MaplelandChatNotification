#include "packet_parser.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>

#define KEYWORDS_FILE "keywords.txt"

bool whisper_alert = false; // 귓말 알림 기본값 off
bool whisper_set = false;   // 중복 방지용

std::vector<Keyword> keywords; // 전역 키워드 리스트

void ParseKeywords(HANDLE hFile, std::ifstream* file, std::vector<Keyword>& keywords);
void PrintKeywords(const std::vector<Keyword>& keywords);
void CreateDefaultKeywordFile();

void LoadKeywords() {
    std::ifstream file(KEYWORDS_FILE, std::ios::in);
    if (!file) {
        std::cout << "키워드 파일이 존재하지 않습니다. 새로 생성합니다...\n";
        CreateDefaultKeywordFile();
        file.open(KEYWORDS_FILE, std::ios::in); // 파일 다시 열기
        if (!file) {
            std::cerr << "파일 생성 실패!\n";
            return;
        }
    }

    // 파일 잠금 설정 (쓰기 방지)
    HANDLE hFile = CreateFileA(KEYWORDS_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "파일 잠금 실패.\n";
        return;
    }

    // 올바르게 참조 전달
    ParseKeywords(hFile, &file, keywords);

    // 키워드 출력 함수 호출
    PrintKeywords(keywords);
}

void ParseKeywords(HANDLE hFile, std::ifstream* file, std::vector<Keyword>& keywords) {
    std::string line;
    std::vector<bool> comment_stack;  // 스택을 이용한 주석 감지

    while (std::getline(*file, line)) {
        size_t pos = 0;

        // 스택 방식으로 주석 처리
        while ((pos = line.find("/*", pos)) != std::string::npos) {
            comment_stack.push_back(true); // `/*` 발견 시 푸시
            pos += 2;
        }
        pos = 0;
        while ((pos = line.find("*/", pos)) != std::string::npos) {
            if (!comment_stack.empty()) {
                comment_stack.pop_back(); // `*/` 발견 시 팝
            }
            pos += 2;
        }

        if (!comment_stack.empty()) continue; // 주석 내부는 무시

        // 귓말(수신) 알림 설정 감지 (중복 방지)
        if (!whisper_set) {
            if (line.find("&{seton()}") != std::string::npos) {
                whisper_alert = true;
                whisper_set = true; // 중복 설정 방지
            }
            if (line.find("&{setoff()}") != std::string::npos) {
                whisper_alert = false;
                whisper_set = true; // 중복 설정 방지
            }
        }

        // 키워드 파싱 (`${타입,키워드}` 형태)
        pos = 0;
        while ((pos = line.find("${", pos)) != std::string::npos) {
            size_t end_pos = line.find("}", pos);
            if (end_pos == std::string::npos) break; // 닫는 `}`가 없으면 무시

            std::string token = line.substr(pos + 2, end_pos - pos - 2); // `${}` 내부 추출
            size_t comma_pos = token.find(",");
            if (comma_pos != std::string::npos) {
                int type = std::stoi(token.substr(0, comma_pos)); // 타입 추출
                std::string word = token.substr(comma_pos + 1); // 키워드 추출
                keywords.push_back({ type, word });
            }
            pos = end_pos + 1;
        }
    }

    file->close();
    CloseHandle(hFile);
}

// 키워드 출력 함수
void PrintKeywords(const std::vector<Keyword>& keywords) {
    std::cout << "귓말(수신) 알림: " << (whisper_alert ? "ON" : "OFF") << std::endl;
    for (const auto& kw : keywords) {
        std::cout << "타입: " << kw.type << ", 키워드: " << kw.word << std::endl;
    }
}

void CreateDefaultKeywordFile() {
    std::ofstream file(KEYWORDS_FILE);
    if (file) {
        file << "/* 주석입니다.\n"
            << "키워드파일작성 규칙입니다.\n"
            << "등록된 키워드는 소리 알림이 나옵니다.\n"
            << "1. 키워드 형식은 ${타입,키워드}\n"
            << "2. 주석 형식은 /*  */\n"
            << "3. 타입 종류는\n"
            << "타입0 = 모든 채팅(전챗, 고확, 귓말 전부포함)\n"
            << "타입1 = 전체 채팅\n"
            << "타입2 = 펫 채팅?(정확히는 잘 모름) <- 아직 완성안됨\n"
            << "타입3 = 채널 채팅\n"
            << "타입4 = 고확\n"
            << "타입5 = 귓말(송신) <- 아직 완성안됨\n"
            << "타입6 = 귓말(수신)\n\n"
            << "4. 귓말(수신) 알림설정 방법(두개중 하나만 쓸것)\n"
            << "&{setoff()} = 귓말(수신) 소리알림 끄기\n"
            << "&{seton()} = 귓말(수신) 소리알림 켜기\n"
            << "귓말(수신)알림은 기본값으로 off이 되어있습니다.\n"
            << "on설정되면 키워드랑 상관없이 귓말(수신)은 계속 소리 알림이 나옵니다.\n"
            << "---------------------예시---------------------\n"
            << "&{seton()}${3,어금니}${4,확투}${1,자리}\n\n"
            << "*/ 주석의 끝입니다.\n";
        file.close();
        std::cout << "기본 키워드 파일이 생성되었습니다.\n";
    }
    else {
        std::cerr << "키워드 파일을 생성하는 데 실패했습니다!\n";
    }
}
