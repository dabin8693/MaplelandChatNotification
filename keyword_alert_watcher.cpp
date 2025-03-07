#include "packet_parser.h"
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")

void alertSoundLoop() {
    while (isRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(3)); // 3초 대기

        if (isTrigger) {
            // Beep(3000, 500); // 1000Hz, 500ms 소리 출력
            PlaySound(TEXT("띠-딩1.6배.wav"), NULL, SND_FILENAME | SND_ASYNC);
            isTrigger = 0; // 알림 후 리셋
        }
    }
}