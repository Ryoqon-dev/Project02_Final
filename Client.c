// 프로젝트명 : 당신의 지역은 괜찮아요? (Is it safe around where you LIVE?)
// 파일명 : Client.c
/*  설명  : 치안 통계 분석 서버에 접속하여 로그인, 회원가입, 지역별 범죄 및 치안 인프라 통계 조회,
            실질 치안 위험도 분석과 맞춤형 가이드라인 제공 기능을 수행하는 클라이언트 프로그램 */
// 작성자 : 2023243047 박교범
// 작성일 : 2026-05-25 ~ 2026-06-15

#include "Common.h"

static SOCKET gSock = INVALID_SOCKET;
static int gLoggedIn = 0;

static void PauseScreen(void);
static void TrimNewline(char* str);
static int GetStringInput(char* buffer, int maxSize, const char* prompt);
static int GetIntInput(int* value, const char* prompt);
static int RequestAndShow(PacketType type, const char* payload, int pauseAfter);
static int RequestText(PacketType type, const char* payload, char* out, int outSize);
static int SelectProvince(void);
static int SelectCity(int provinceIndex);
static void ShowInitialMenu(void);
static void ShowMainMenu(void);

int main(void) {
    WSADATA wsaData;
    SOCKADDR_IN servAdr;

    /* 콘솔 입출력 코드페이지를 UTF-8로 설정함 */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[오류] 네트워크 초기화 실패\n");
        return 1;
    }

    gSock = socket(PF_INET, SOCK_STREAM, 0);
    if (gSock == INVALID_SOCKET) {
        printf("[오류] 소켓 생성 실패\n");
        WSACleanup();
        return 1;
    }

    memset(&servAdr, 0, sizeof(servAdr));
    servAdr.sin_family = AF_INET;
    servAdr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servAdr.sin_port = htons(PORT);

    printf("치안 통계 분석 서버에 연결하는 중입니다...\n");
    if (connect(gSock, (SOCKADDR*)&servAdr, sizeof(servAdr)) == SOCKET_ERROR) {
        printf("\n[연결 실패] Server.exe를 먼저 실행했는지 확인하세요.\n");
        closesocket(gSock);
        WSACleanup();
        return 1;
    }

    while (1) {
        if (gLoggedIn) ShowMainMenu();
        else ShowInitialMenu();
    }
}

/* 결과 화면을 사용자가 읽을 수 있도록 엔터 입력을 기다림 */
static void PauseScreen(void) {
    char tmp[8];
    printf("\n계속하려면 엔터를 누르세요...");
    fgets(tmp, sizeof(tmp), stdin);
}

/* 입력 문자열 끝의 개행 문자를 제거함 */
static void TrimNewline(char* str) {
    int len;
    if (!str) return;
    len = (int)strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/* 프롬프트를 출력하고 한 줄 문자열 입력을 받음 */
static int GetStringInput(char* buffer, int maxSize, const char* prompt) {
    printf("%s", prompt);
    if (!fgets(buffer, maxSize, stdin)) return 0;
    TrimNewline(buffer);
    return (int)strlen(buffer);
}

/* 프롬프트를 출력하고 정수 메뉴 입력을 받음 */
static int GetIntInput(int* value, const char* prompt) {
    char buf[32];
    printf("%s", prompt);
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    *value = atoi(buf);
    return 1;
}

/* 서버에 목록 요청을 보내고 응답 문자열을 호출자 버퍼에 저장함 */
static int RequestText(PacketType type, const char* payload, char* out, int outSize) {
    PacketHeader hdr;

    if (SendPacket(gSock, type, payload) != 0) {
        snprintf(out, outSize, "[오류] 서버로 요청을 보내지 못했습니다.");
        return -1;
    }

    if (RecvPacket(gSock, &hdr, out, outSize) != 0) {
        printf("\n[오류] 서버와의 연결이 끊어졌습니다.\n");
        closesocket(gSock);
        WSACleanup();
        exit(1);
    }

    if (hdr.type == PKT_ERROR_RES) return -1;
    return 0;
}

/* 서버에 기능 요청을 보내고 응답을 화면에 출력함 */
static int RequestAndShow(PacketType type, const char* payload, int pauseAfter) {
    PacketHeader hdr;
    char res[BIG_BUF_SIZE];

    if (SendPacket(gSock, type, payload) != 0) {
        printf("\n[오류] 서버로 요청을 보내지 못했습니다.\n");
        PauseScreen();
        return -1;
    }

    if (RecvPacket(gSock, &hdr, res, sizeof(res)) != 0) {
        printf("\n[오류] 서버와의 연결이 끊어졌습니다.\n");
        closesocket(gSock);
        WSACleanup();
        exit(1);
    }

    if (hdr.type == PKT_LOGIN_RES) {
        if (res[0] == '1') {
            gLoggedIn = 1;
            printf("\n[성공] 로그인되었습니다.\n");
        } else {
            printf("\n[실패] 아이디 또는 비밀번호가 올바르지 않습니다.\n");
        }
    } else if (hdr.type == PKT_RES_TEXT || hdr.type == PKT_ERROR_RES) {
        printf("\n%s\n", res);
    } else {
        printf("\n[안내] 알 수 없는 서버 응답을 받았습니다.\n");
    }

    if (pauseAfter) PauseScreen();
    return 0;
}

/* 서버에서 도/시 목록을 받아 출력하고 사용자의 선택 번호를 반환함 */
static int SelectProvince(void) {
    char list[BIG_BUF_SIZE];
    int provinceIndex = 0;

    system("cls");
    if (RequestText(PKT_REQ_PROVINCE_LIST, "", list, sizeof(list)) != 0) {
        printf("\n%s\n", list);
        PauseScreen();
        return 0;
    }
    printf("%s\n", list);
    if (!GetIntInput(&provinceIndex, "도/시 번호 선택: ")) return 0;
    return provinceIndex;
}

/* 선택한 도/시에 속한 시/군/구 목록을 받아 출력하고 선택 번호를 반환함 */
static int SelectCity(int provinceIndex) {
    char payload[32];
    char list[BIG_BUF_SIZE];
    int cityIndex = 0;

    snprintf(payload, sizeof(payload), "%d", provinceIndex);
    system("cls");
    if (RequestText(PKT_REQ_CITY_LIST, payload, list, sizeof(list)) != 0) {
        printf("\n%s\n", list);
        PauseScreen();
        return 0;
    }
    printf("%s\n", list);
    if (!GetIntInput(&cityIndex, "시/군/구 번호 선택: ")) return 0;
    return cityIndex;
}

/* 로그인 전 초기 메뉴를 출력하고 로그인, 회원가입, 종료를 처리함 */
static void ShowInitialMenu(void) {
    int menu = 0;

    system("cls");
    printf("==================================================\n");
    printf("      당신의 지역은 괜찮아요?\n");
    printf("      Is it safe around where you LIVE?\n");
    printf("==================================================\n");
    printf(" [1] 로그인\n");
    printf(" [2] 회원가입\n");
    printf(" [3] 종료\n");
    printf("==================================================\n");

    if (!GetIntInput(&menu, "메뉴 번호 선택: ")) return;

    if (menu == 1) {
        char id[NAME_SIZE] = {0};
        char pw[NAME_SIZE] = {0};
        char payload[BUF_SIZE];

        printf("\n[로그인]\n");
        GetStringInput(id, sizeof(id), "아이디: ");
        GetStringInput(pw, sizeof(pw), "비밀번호: ");
        snprintf(payload, sizeof(payload), "%s\t%s", id, pw);
        RequestAndShow(PKT_LOGIN_REQ, payload, 1);
    } else if (menu == 2) {
        char id[NAME_SIZE] = {0};
        char pw[NAME_SIZE] = {0};
        char region[REGION_SIZE] = {0};
        int age = 0;
        char payload[BUF_SIZE];

        printf("\n[회원가입]\n");
        GetStringInput(id, sizeof(id), "사용자 ID: ");
        GetStringInput(pw, sizeof(pw), "사용자 PW: ");
        GetIntInput(&age, "나이: ");
        GetStringInput(region, sizeof(region), "거주 지역명(예: 충남 아산시): ");

        snprintf(payload, sizeof(payload), "%s\t%s\t%d\t%s", id, pw, age, region);
        RequestAndShow(PKT_REGISTER_REQ, payload, 1);
    } else if (menu == 3) {
        printf("\n프로그램을 종료합니다.\n");
        closesocket(gSock);
        WSACleanup();
        exit(0);
    } else {
        printf("\n잘못된 메뉴입니다.\n");
        PauseScreen();
    }
}

/* 로그인 후 지역 치안 분석 메뉴를 출력하고 선택한 기능을 실행함 */
static void ShowMainMenu(void) {
    int menu = 0;

    system("cls");
    printf("==================================================\n");
    printf("        지역 치안 분석 메뉴\n");
    printf("==================================================\n");
    printf(" [1] 범죄 발생 통계 현황\n");
    printf(" [2] 치안 인프라 통계 현황\n");
    printf(" [3] 실질 치안 위험도와 맞춤형 가이드라인\n");
    printf(" [4] 로그아웃\n");
    printf("==================================================\n");

    if (!GetIntInput(&menu, "기능 번호 선택: ")) return;

    if (menu == 1) {
        int provinceIndex = SelectProvince();
        int cityIndex;
        char payload[64];
        if (provinceIndex <= 0) return;
        cityIndex = SelectCity(provinceIndex);
        if (cityIndex <= 0) return;
        snprintf(payload, sizeof(payload), "%d\t%d", provinceIndex, cityIndex);
        RequestAndShow(PKT_REQ_01_CRIME_TOP3, payload, 1);
    } else if (menu == 2) {
        int provinceIndex = SelectProvince();
        char payload[32];
        if (provinceIndex <= 0) return;
        snprintf(payload, sizeof(payload), "%d", provinceIndex);
        RequestAndShow(PKT_REQ_03_POLICE_COUNT, payload, 1);
    } else if (menu == 3) {
        int provinceIndex = SelectProvince();
        int cityIndex;
        char payload[64];
        if (provinceIndex <= 0) return;
        cityIndex = SelectCity(provinceIndex);
        if (cityIndex <= 0) return;
        snprintf(payload, sizeof(payload), "%d\t%d", provinceIndex, cityIndex);
        RequestAndShow(PKT_REQ_05_REAL_RISK, payload, 1);
    } else if (menu == 4) {
        gLoggedIn = 0;
        printf("\n로그아웃되었습니다.\n");
        PauseScreen();
    } else {
        printf("\n잘못된 메뉴입니다.\n");
        PauseScreen();
    }
}
