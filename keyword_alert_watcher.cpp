#include "packet_parser.h"
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")

void alertSoundLoop() {
    while (isRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(3)); // 3�� ���

        if (isTrigger) {
            // Beep(3000, 500); // 1000Hz, 500ms �Ҹ� ���
            PlaySound(TEXT("��-��1.6��.wav"), NULL, SND_FILENAME | SND_ASYNC);
            isTrigger = 0; // �˸� �� ����
        }
    }
}