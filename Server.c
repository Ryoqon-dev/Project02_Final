// 프로젝트명 : 당신의 지역은 괜찮아요? (Is it safe around where you LIVE?)
// 파일명 : Server.c
/*  설명  : 치안 통계 분석 서버 프로그램으로 클라이언트의 로그인 및 회원가입 요청 처리,
            지역별 범죄 및 치안 인프라 통계 조회, 실질 치안 위험도 분석과 맞춤형 가이드라인 제공 기능 구현 */
// 작성자 : 2023243047 박교범
// 작성일 : 2026-05-25 ~ 2026-06-15

#include "Common.h"
#include <stdarg.h>

typedef struct {
    char regionName[REGION_SIZE];
} RegionHeader;

typedef struct UserNode {
    UserInfo info;
    struct UserNode* next;
} UserNode;

typedef struct {
    char name[REGION_SIZE * 2];
    int count;
} CrimeRank;

typedef struct {
    CrimeRank items[MAX_CRIME_ROWS];
    int size;
} CrimeMaxHeap;

typedef struct {
    char shortName[32];
    char officialName[64];
    char crimePrefix[32];
} ProvinceInfo;

typedef struct {
    char name[REGION_SIZE];
    int officerCount;
    int population;
    int popPerOfficer;
} PoliceSummary;

static const ProvinceInfo gProvinces[] = {
    {"서울", "서울특별시", "서울"},
    {"부산", "부산광역시", "부산"},
    {"대구", "대구광역시", "대구"},
    {"인천", "인천광역시", "인천"},
    {"광주", "광주광역시", "광주"},
    {"대전", "대전광역시", "대전"},
    {"울산", "울산광역시", "울산"},
    {"세종", "세종자치시", "세종"},
    {"경기", "경기도", "경기도"},
    {"강원", "강원도", "강원도"},
    {"충북", "충청북도", "충북"},
    {"충남", "충청남도", "충남"},
    {"전북", "전라북도", "전북"},
    {"전남", "전라남도", "전남"},
    {"경북", "경상북도", "경북"},
    {"경남", "경상남도", "경남"},
    {"제주", "제주특별자치도", "제주"}
};

static ClientNode* gClients = NULL;
static UserNode* gUsers = NULL;
static CrimeNode* gCrimes = NULL;
static PoliceNode* gPolice = NULL;
static RegionHeader gRegions[MAX_REGIONS];
static int gRegionCount = 0;
static HANDLE gMutex;
static double gNationalAvgCrime = 0.0;
static double gNationalAvgPeoplePerOfficer = 0.0;

static unsigned WINAPI ClientHandler(void* arg);
static void HandleClientRequest(SOCKET sock, PacketHeader hdr, char* payload);
static void TrimNewline(char* str);
static void CleanText(char* str);
static int ConvertBytesToUtf8(const char* src, char* out, int outSize);
static int ReadTextLine(FILE* fp, char* out, int outSize);
static int LoadUserDatabase(void);
static int AppendUserToFile(const UserInfo* user);
static UserNode* FindUserById(const char* id);
static int ParseCSVFiles(void);
static void CalculateAverages(void);
static int ValidateLoadedData(void);
static void SortCrimeRanks(CrimeRank* list, int count);
static void HeapPush(CrimeMaxHeap* heap, const CrimeRank* item);
static int HeapPop(CrimeMaxHeap* heap, CrimeRank* out);
static int RegionBelongsToProvince(int regionIndex, int provinceIndex);
static int ResolveRegionSelection(const char* payload);
static int ResolveCityIndex(int provinceIndex, int cityNumber);
static long long GetRegionCrimeTotal(int regionIndex);
static int GetPoliceSummaryByProvince(int provinceIndex, PoliceSummary* out);
static int ProvinceIndexFromRegion(int regionIndex);
static void BuildProvinceList(char* out, int outSize);
static void BuildCityList(int provinceIndex, char* out, int outSize);
static void BuildCrimeAndSafety(int regionIndex, char* out, int outSize);
static void BuildPoliceAndResponse(int provinceIndex, char* out, int outSize);
static void BuildRiskAndGuide(int regionIndex, char* out, int outSize);
static const char* GetCrimeGuide(const char* crimeName);
static void AppendText(char* out, int outSize, int* used, const char* text);
static void AppendFormat(char* out, int outSize, int* used, const char* fmt, ...);
static void SendText(SOCKET sock, const char* text);
static void SendError(SOCKET sock, const char* text);
static void CleanupResources(void);

int main(void) {
    WSADATA wsaData;
    SOCKET servSock;
    SOCKADDR_IN servAdr;

    /* 콘솔 입출력 코드페이지를 UTF-8로 설정함 */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    printf("==================================================\n");
    printf("      치안 통계 분석 서버를 시작합니다.\n");
    printf("==================================================\n");

    gMutex = CreateMutex(NULL, FALSE, NULL);
    if (!gMutex) return 1;

    if (LoadUserDatabase() != 0) {
        printf("[경고] users.txt를 만들거나 읽지 못했습니다.\n");
    }
    if (ParseCSVFiles() != 0) {
        printf("[오류] CrimeStats.csv 또는 PoliceStats.csv 로드 실패\n");
        return 1;
    }
    CalculateAverages();
    if (ValidateLoadedData() != 0) {
        printf("[오류] 통계 데이터 검증 실패. CSV 파일 내용을 확인하세요.\n");
        CleanupResources();
        return 1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[오류] WSAStartup 실패\n");
        return 1;
    }

    servSock = socket(PF_INET, SOCK_STREAM, 0);
    if (servSock == INVALID_SOCKET) {
        printf("[오류] 서버 소켓 생성 실패\n");
        WSACleanup();
        return 1;
    }

    memset(&servAdr, 0, sizeof(servAdr));
    servAdr.sin_family = AF_INET;
    servAdr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAdr.sin_port = htons(PORT);

    {
        int opt = 1;
        setsockopt(servSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    }

    if (bind(servSock, (SOCKADDR*)&servAdr, sizeof(servAdr)) == SOCKET_ERROR) {
        printf("[오류] 포트 %d 바인드 실패. 이미 실행 중인 서버가 있는지 확인하세요.\n", PORT);
        closesocket(servSock);
        WSACleanup();
        return 1;
    }
    if (listen(servSock, 5) == SOCKET_ERROR) {
        printf("[오류] listen 실패\n");
        closesocket(servSock);
        WSACleanup();
        return 1;
    }

    printf("[성공] 서버 준비 완료. 포트: %d\n", PORT);
    printf("[정보] 범죄 지역 %d개, 전국 평균 범죄 %.1f건, 평균 담당 인구 %.1f명\n",
        gRegionCount, gNationalAvgCrime, gNationalAvgPeoplePerOfficer);

    while (1) {
        SOCKADDR_IN clntAdr;
        int clntAdrSize = sizeof(clntAdr);
        SOCKET clntSock = accept(servSock, (SOCKADDR*)&clntAdr, &clntAdrSize);
        ClientNode* node;
        SOCKET* sockPtr;

        if (clntSock == INVALID_SOCKET) continue;

        node = (ClientNode*)calloc(1, sizeof(ClientNode));
        sockPtr = (SOCKET*)malloc(sizeof(SOCKET));
        if (!node || !sockPtr) {
            free(node);
            free(sockPtr);
            closesocket(clntSock);
            continue;
        }

        node->sock = clntSock;
        strcpy(node->id, "guest");

        WaitForSingleObject(gMutex, INFINITE);
        node->next = gClients;
        gClients = node;
        ReleaseMutex(gMutex);

        printf("[연결] 클라이언트 접속: %s\n", inet_ntoa(clntAdr.sin_addr));

        *sockPtr = clntSock;
        _beginthreadex(NULL, 0, ClientHandler, sockPtr, 0, NULL);
    }

    CleanupResources();
    closesocket(servSock);
    WSACleanup();
    CloseHandle(gMutex);
    return 0;
}

/* 클라이언트별 스레드에서 패킷을 반복 수신하고 연결 종료 시 목록에서 제거함 */
static unsigned WINAPI ClientHandler(void* arg) {
    SOCKET sock = *((SOCKET*)arg);
    PacketHeader hdr;
    char payload[BIG_BUF_SIZE];
    ClientNode* curr;
    ClientNode* prev;

    free(arg);

    while (RecvPacket(sock, &hdr, payload, sizeof(payload)) == 0) {
        HandleClientRequest(sock, hdr, payload);
    }

    WaitForSingleObject(gMutex, INFINITE);
    curr = gClients;
    prev = NULL;
    while (curr) {
        if (curr->sock == sock) {
            if (prev) prev->next = curr->next;
            else gClients = curr->next;
            printf("[해제] 클라이언트 종료: %s\n", curr->id);
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    ReleaseMutex(gMutex);

    closesocket(sock);
    return 0;
}

/* 문자열 끝의 개행 문자를 제거함 */
static void TrimNewline(char* str) {
    int len;
    if (!str) return;
    len = (int)strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/* CSV와 사용자 파일에서 읽은 문자열의 BOM, 공백, 따옴표를 정리함 */
static void CleanText(char* str) {
    char* start;
    char* end;
    unsigned char* bytes;

    if (!str) return;
    bytes = (unsigned char*)str;
    if (bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) {
        memmove(str, str + 3, strlen(str + 3) + 1);
    }

    start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) end--;
    *end = '\0';

    if (*start == '"' && strlen(start) >= 2 && start[strlen(start) - 1] == '"') {
        start[strlen(start) - 1] = '\0';
        start++;
    }
    if (start != str) memmove(str, start, strlen(start) + 1);
}

/* UTF-8 또는 시스템 기본 코드페이지 문자열을 UTF-8 문자열로 변환함 */
static int ConvertBytesToUtf8(const char* src, char* out, int outSize) {
    wchar_t wide[BIG_BUF_SIZE];
    int wlen;

    out[0] = '\0';
    wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, -1, wide, BIG_BUF_SIZE);
    if (wlen <= 0) wlen = MultiByteToWideChar(CP_ACP, 0, src, -1, wide, BIG_BUF_SIZE);
    if (wlen <= 0) return -1;
    return WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, outSize, NULL, NULL) > 0 ? 0 : -1;
}

/* 파일에서 한 줄을 읽고 UTF-8 문자열로 정규화함 */
static int ReadTextLine(FILE* fp, char* out, int outSize) {
    char raw[BIG_BUF_SIZE];
    if (!fgets(raw, sizeof(raw), fp)) return 0;
    if (ConvertBytesToUtf8(raw, out, outSize) != 0) {
        strncpy(out, raw, outSize - 1);
        out[outSize - 1] = '\0';
    }
    TrimNewline(out);
    return 1;
}

/* 연결 리스트에서 아이디가 일치하는 사용자를 찾음 */
static UserNode* FindUserById(const char* id) {
    UserNode* curr = gUsers;
    while (curr) {
        if (strcmp(curr->info.id, id) == 0) return curr;
        curr = curr->next;
    }
    return NULL;
}

/* users.txt 파일을 읽어 사용자 연결 리스트를 구성함 */
static int LoadUserDatabase(void) {
    FILE* fp = fopen("users.txt", "rb");
    char line[BUF_SIZE];

    if (!fp) {
        fp = fopen("users.txt", "wb");
        if (!fp) return -1;
        fclose(fp);
        return 0;
    }

    while (ReadTextLine(fp, line, sizeof(line))) {
        UserNode* node;
        char* id = strtok(line, "\t");
        char* pw = strtok(NULL, "\t");
        char* age = strtok(NULL, "\t");
        char* region = strtok(NULL, "\t");
        if (!id || !pw || !age) continue;

        node = (UserNode*)calloc(1, sizeof(UserNode));
        if (!node) continue;
        strncpy(node->info.id, id, NAME_SIZE - 1);
        strncpy(node->info.pw, pw, NAME_SIZE - 1);
        node->info.age = atoi(age);
        if (region) strncpy(node->info.region, region, REGION_SIZE - 1);
        CleanText(node->info.region);

        node->next = gUsers;
        gUsers = node;
    }

    fclose(fp);
    return 0;
}

/* 신규 회원 정보를 users.txt 파일 끝에 저장함. */
static int AppendUserToFile(const UserInfo* user) {
    FILE* fp = fopen("users.txt", "ab");
    if (!fp) return -1;
    fprintf(fp, "%s\t%s\t%d\t%s\n", user->id, user->pw, user->age, user->region);
    fclose(fp);
    return 0;
}

/* CrimeStats.csv와 PoliceStats.csv를 읽어 서버 메모리 자료구조로 적재함 */
static int ParseCSVFiles(void) {
    FILE* fp;
    char line[BIG_BUF_SIZE];
    char* token;
    int i;

    fp = fopen("CrimeStats.csv", "rb");
    if (!fp) return -1;

    if (ReadTextLine(fp, line, sizeof(line))) {
        strtok(line, ",");
        strtok(NULL, ",");
        gRegionCount = 0;
        while ((token = strtok(NULL, ",")) != NULL && gRegionCount < MAX_REGIONS) {
            strncpy(gRegions[gRegionCount].regionName, token, REGION_SIZE - 1);
            gRegions[gRegionCount].regionName[REGION_SIZE - 1] = '\0';
            CleanText(gRegions[gRegionCount].regionName);
            gRegionCount++;
        }
    }

    while (ReadTextLine(fp, line, sizeof(line))) {
        CrimeNode* node;
        char* major = strtok(line, ",");
        char* minor = strtok(NULL, ",");
        if (!major || !minor) continue;

        node = (CrimeNode*)calloc(1, sizeof(CrimeNode));
        if (!node) continue;
        strncpy(node->majorType, major, REGION_SIZE - 1);
        strncpy(node->minorType, minor, REGION_SIZE - 1);
        CleanText(node->majorType);
        CleanText(node->minorType);

        for (i = 0; i < gRegionCount; i++) {
            char* val = strtok(NULL, ",");
            node->counts[i] = val ? atoi(val) : 0;
        }
        node->next = gCrimes;
        gCrimes = node;
    }
    fclose(fp);

    fp = fopen("PoliceStats.csv", "rb");
    if (!fp) return -1;
    ReadTextLine(fp, line, sizeof(line));

    while (ReadTextLine(fp, line, sizeof(line))) {
        PoliceNode* node;
        char* region = strtok(line, ",");
        char* officers = strtok(NULL, ",");
        char* population = strtok(NULL, ",");
        char* perOfficer = strtok(NULL, ",");
        if (!region || !officers || !population || !perOfficer) continue;

        node = (PoliceNode*)calloc(1, sizeof(PoliceNode));
        if (!node) continue;
        strncpy(node->regionName, region, REGION_SIZE - 1);
        CleanText(node->regionName);
        node->officerCount = atoi(officers);
        node->population = atoi(population);
        node->popPerOfficer = atoi(perOfficer);

        if (node->officerCount <= 0 || node->population <= 0 || node->popPerOfficer <= 0) {
            free(node);
            continue;
        }

        node->next = gPolice;
        gPolice = node;
    }
    fclose(fp);
    return 0;
}

/* 적재된 통계 데이터가 요청 처리에 필요한 최소 조건을 만족하는지 검증함 */
static int ValidateLoadedData(void) {
    int provinceIndex;
    CrimeNode* crime = gCrimes;
    PoliceNode* police = gPolice;

    if (gRegionCount <= 0 || gRegionCount > MAX_REGIONS) {
        printf("[검증 실패] 범죄 지역 개수가 올바르지 않습니다. regionCount=%d\n", gRegionCount);
        return -1;
    }
    if (!crime) {
        printf("[검증 실패] 범죄 통계 행이 없습니다.\n");
        return -1;
    }
    if (!police) {
        printf("[검증 실패] 경찰 통계 행이 없습니다.\n");
        return -1;
    }
    if (gNationalAvgCrime <= 0.0 || gNationalAvgPeoplePerOfficer <= 0.0) {
        printf("[검증 실패] 전국 평균 계산값이 올바르지 않습니다.\n");
        return -1;
    }

    for (provinceIndex = 1; provinceIndex <= (int)(sizeof(gProvinces) / sizeof(gProvinces[0])); provinceIndex++) {
        int foundCity = 0;
        int i;
        PoliceSummary summary;

        for (i = 0; i < gRegionCount; i++) {
            if (RegionBelongsToProvince(i, provinceIndex)) {
                foundCity = 1;
                break;
            }
        }
        if (!foundCity) {
            printf("[검증 실패] %s에 해당하는 범죄 지역이 없습니다.\n", gProvinces[provinceIndex - 1].officialName);
            return -1;
        }
        if (!GetPoliceSummaryByProvince(provinceIndex, &summary)) {
            printf("[검증 실패] %s에 해당하는 경찰 통계가 없습니다.\n", gProvinces[provinceIndex - 1].officialName);
            return -1;
        }
    }

    printf("[검증] CSV 데이터와 지역 매핑 검증을 완료했습니다.\n");
    return 0;
}

/* 전체 범죄 평균과 경찰 담당 인구 평균을 계산함 */
static void CalculateAverages(void) {
    long long totalCrime = 0;
    long long totalPopulation = 0;
    long long totalOfficers = 0;
    int i;
    CrimeNode* c = gCrimes;
    PoliceNode* p = gPolice;

    while (c) {
        for (i = 0; i < gRegionCount; i++) totalCrime += c->counts[i];
        c = c->next;
    }
    if (gRegionCount > 0) gNationalAvgCrime = (double)totalCrime / gRegionCount;

    while (p) {
        totalPopulation += p->population;
        totalOfficers += p->officerCount;
        p = p->next;
    }
    if (totalOfficers > 0) gNationalAvgPeoplePerOfficer = (double)totalPopulation / totalOfficers;
}

/* 범죄 순위 항목 두 개를 교환함 */
static void SwapCrimeRank(CrimeRank* a, CrimeRank* b) {
    CrimeRank tmp = *a;
    *a = *b;
    *b = tmp;
}

/* 최대 힙을 이용해 범죄 건수를 내림차순으로 정렬함 */
static void SortCrimeRanks(CrimeRank* list, int count) {
    CrimeMaxHeap heap;
    CrimeRank item;
    int i;

    heap.size = 0;
    for (i = 0; i < count; i++) {
        HeapPush(&heap, &list[i]);
    }

    for (i = 0; i < count; i++) {
        if (HeapPop(&heap, &item)) list[i] = item;
    }
}

/* 최대 힙에 범죄 순위 항목을 삽입함 */
static void HeapPush(CrimeMaxHeap* heap, const CrimeRank* item) {
    int idx;
    if (!heap || !item || heap->size >= MAX_CRIME_ROWS) return;

    idx = heap->size++;
    heap->items[idx] = *item;

    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (heap->items[parent].count >= heap->items[idx].count) break;
        SwapCrimeRank(&heap->items[parent], &heap->items[idx]);
        idx = parent;
    }
}

/* 최대 힙에서 가장 큰 범죄 순위 항목을 꺼냄 */
static int HeapPop(CrimeMaxHeap* heap, CrimeRank* out) {
    int idx = 0;

    if (!heap || !out || heap->size <= 0) return 0;
    *out = heap->items[0];
    heap->items[0] = heap->items[--heap->size];

    while (1) {
        int left = idx * 2 + 1;
        int right = left + 1;
        int largest = idx;

        if (left < heap->size && heap->items[left].count > heap->items[largest].count) {
            largest = left;
        }
        if (right < heap->size && heap->items[right].count > heap->items[largest].count) {
            largest = right;
        }
        if (largest == idx) break;

        SwapCrimeRank(&heap->items[idx], &heap->items[largest]);
        idx = largest;
    }

    return 1;
}

/* 특정 범죄 지역이 선택한 도/시에 속하는지 확인함 */
static int RegionBelongsToProvince(int regionIndex, int provinceIndex) {
    const char* region;
    const char* prefix;
    if (regionIndex < 0 || regionIndex >= gRegionCount) return 0;
    if (provinceIndex < 1 || provinceIndex > (int)(sizeof(gProvinces) / sizeof(gProvinces[0]))) return 0;
    region = gRegions[regionIndex].regionName;
    prefix = gProvinces[provinceIndex - 1].crimePrefix;
    return strncmp(region, prefix, strlen(prefix)) == 0;
}

/* 도/시 번호와 시/군/구 번호를 실제 범죄 지역 배열 인덱스로 변환함 */
static int ResolveCityIndex(int provinceIndex, int cityNumber) {
    int i;
    int count = 0;
    if (cityNumber <= 0) return -1;
    for (i = 0; i < gRegionCount; i++) {
        if (RegionBelongsToProvince(i, provinceIndex)) {
            count++;
            if (count == cityNumber) return i;
        }
    }
    return -1;
}

/* 클라이언트 Payload의 "도/시번호\t시군구번호" 값을 범죄 지역 인덱스로 변환함 */
static int ResolveRegionSelection(const char* payload) {
    char buf[BUF_SIZE];
    char* p;
    char* c;
    if (!payload) return -1;
    strncpy(buf, payload, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    p = strtok(buf, "\t");
    c = strtok(NULL, "\t");
    if (!p || !c) return -1;
    return ResolveCityIndex(atoi(p), atoi(c));
}

/* 선택한 범죄 지역의 전체 범죄 발생 건수를 합산함 */
static long long GetRegionCrimeTotal(int regionIndex) {
    long long total = 0;
    CrimeNode* curr = gCrimes;
    while (curr) {
        total += curr->counts[regionIndex];
        curr = curr->next;
    }
    return total;
}

/* 선택한 도/시의 경찰 통계를 요약하고 경기도 남부/북부처럼 분리된 행은 합산함 */
static int GetPoliceSummaryByProvince(int provinceIndex, PoliceSummary* out) {
    const ProvinceInfo* province;
    PoliceNode* curr;
    int found = 0;
    int totalOfficers = 0;
    int totalPopulation = 0;

    if (!out || provinceIndex < 1 || provinceIndex > (int)(sizeof(gProvinces) / sizeof(gProvinces[0]))) return 0;
    province = &gProvinces[provinceIndex - 1];
    memset(out, 0, sizeof(*out));
    strncpy(out->name, province->officialName, sizeof(out->name) - 1);

    curr = gPolice;
    while (curr) {
        int match = 0;
        if (provinceIndex == 9) {
            match = strstr(curr->regionName, "경기도") != NULL;
        } else {
            match = strstr(curr->regionName, province->officialName) != NULL ||
                    strstr(province->officialName, curr->regionName) != NULL;
        }
        if (match) {
            totalOfficers += curr->officerCount;
            totalPopulation += curr->population;
            found = 1;
        }
        curr = curr->next;
    }

    if (!found || totalOfficers <= 0) return 0;
    out->officerCount = totalOfficers;
    out->population = totalPopulation;
    out->popPerOfficer = totalPopulation / totalOfficers;
    return 1;
}

/* 범죄 지역명에서 상위 도/시 인덱스를 찾음 */
static int ProvinceIndexFromRegion(int regionIndex) {
    int i;
    for (i = 1; i <= (int)(sizeof(gProvinces) / sizeof(gProvinces[0])); i++) {
        if (RegionBelongsToProvince(regionIndex, i)) return i;
    }
    return -1;
}

/* 클라이언트가 선택할 수 있는 도/시 목록 문자열을 생성함 */
static void BuildProvinceList(char* out, int outSize) {
    int i;
    int used = 0;
    used += snprintf(out + used, outSize - used,
        "도/시 단위 지역을 선택하세요.\n"
        "--------------------------------------------------\n");
    for (i = 0; i < (int)(sizeof(gProvinces) / sizeof(gProvinces[0])); i++) {
        used += snprintf(out + used, outSize - used, "%2d. %-6s (%s)\n",
            i + 1, gProvinces[i].shortName, gProvinces[i].officialName);
        if (used >= outSize) break;
    }
}

/* 선택한 도/시에 속한 시/군/구 목록 문자열을 생성함 */
static void BuildCityList(int provinceIndex, char* out, int outSize) {
    int i;
    int count = 0;
    int used = 0;

    if (provinceIndex < 1 || provinceIndex > (int)(sizeof(gProvinces) / sizeof(gProvinces[0]))) {
        snprintf(out, outSize, "잘못된 도/시 번호입니다.");
        return;
    }

    used += snprintf(out + used, outSize - used,
        "[%s] 시/군/구 지역을 선택하세요.\n"
        "--------------------------------------------------\n",
        gProvinces[provinceIndex - 1].officialName);

    for (i = 0; i < gRegionCount; i++) {
        if (RegionBelongsToProvince(i, provinceIndex)) {
            count++;
            used += snprintf(out + used, outSize - used, "%2d. %s\n", count, gRegions[i].regionName);
            if (used >= outSize) break;
        }
    }

    if (count == 0) snprintf(out, outSize, "해당 도/시에 표시할 시/군/구 데이터가 없습니다.");
}

/* 출력 버퍼에 일반 문자열을 안전하게 이어 붙임 */
static void AppendText(char* out, int outSize, int* used, const char* text) {
    if (!out || !used || !text || *used >= outSize) return;
    *used += snprintf(out + *used, outSize - *used, "%s", text);
    if (*used >= outSize) *used = outSize - 1;
}

/* 출력 버퍼에 형식 문자열을 안전하게 이어 붙임 */
static void AppendFormat(char* out, int outSize, int* used, const char* fmt, ...) {
    va_list args;
    int written;

    if (!out || !used || !fmt || *used >= outSize) return;
    va_start(args, fmt);
    written = vsnprintf(out + *used, outSize - *used, fmt, args);
    va_end(args);

    if (written < 0) return;
    *used += written;
    if (*used >= outSize) *used = outSize - 1;
}

/* 지역별 범죄 발생 현황, 전체 순위, 안전 등급 결과 문자열을 생성함 */
static void BuildCrimeAndSafety(int regionIndex, char* out, int outSize) {
    CrimeRank list[MAX_CRIME_ROWS];
    CrimeNode* c = gCrimes;
    int count = 0;
    int used = 0;
    int i;
    long long total = GetRegionCrimeTotal(regionIndex);
    double ratio = gNationalAvgCrime > 0 ? (double)total / gNationalAvgCrime : 0.0;
    const char* grade = "안전";
    const char* comment = "전국 지역 평균보다 범죄 발생이 낮은 편입니다.";

    while (c && count < MAX_CRIME_ROWS) {
        snprintf(list[count].name, sizeof(list[count].name), "%s - %s", c->majorType, c->minorType);
        list[count].count = c->counts[regionIndex];
        count++;
        c = c->next;
    }
    SortCrimeRanks(list, count);

    if (ratio >= 1.20) {
        grade = "위험";
        comment = "전국 평균보다 범죄 발생이 높습니다. 야간 이동과 귀가 동선을 특히 주의하세요.";
    } else if (ratio >= 0.70) {
        grade = "주의";
        comment = "전국 평균과 비슷한 수준입니다. 생활 안전수칙을 꾸준히 지켜주세요.";
    }

    AppendFormat(out, outSize, &used,
        "\n[%s] 범죄 발생 통계 현황\n"
        "============================================================\n"
        "[요약]\n"
        "- 총 범죄 발생 건수 : %lld건\n"
        "- 전국 지역 평균    : %.1f건\n"
        "- 평균 대비 비율    : %.2f배\n"
        "- 범죄 안전 등급    : %s\n"
        "- 해석              : %s\n\n"
        "[Top 3 범죄 유형]\n"
        "  1. %-28s %7d건\n"
        "  2. %-28s %7d건\n"
        "  3. %-28s %7d건\n"
        "------------------------------------------------------------\n"
        "[전체 범죄 유형별 발생 현황]\n"
        "순위 | 발생 건수 | 범죄 유형\n"
        "-----+-----------+--------------------------------\n",
        gRegions[regionIndex].regionName,
        total, gNationalAvgCrime, ratio, grade, comment,
        list[0].name, list[0].count,
        list[1].name, list[1].count,
        list[2].name, list[2].count);

    for (i = 0; i < count; i++) {
        AppendFormat(out, outSize, &used, "%4d | %7d건 | %s\n",
            i + 1, list[i].count, list[i].name);
        if (used >= outSize - 256) break;
    }

    AppendText(out, outSize, &used,
        "============================================================\n"
        "※ 등급은 공공데이터 원자료가 제공하는 공식 등급이 아니라,\n"
        "   본 프로젝트에서 전국 평균 대비 비율로 산출한 참고 지표입니다.");
}

/* 도/시별 경찰 인프라 통계와 치안 서비스 대응력 결과 문자열을 생성함 */
static void BuildPoliceAndResponse(int provinceIndex, char* out, int outSize) {
    PoliceSummary police;
    double ratio;
    const char* status;

    if (!GetPoliceSummaryByProvince(provinceIndex, &police)) {
        snprintf(out, outSize, "해당 도/시의 경찰 통계를 찾을 수 없습니다.");
        return;
    }

    ratio = gNationalAvgPeoplePerOfficer > 0 ? (double)police.popPerOfficer / gNationalAvgPeoplePerOfficer : 0.0;
    status = police.popPerOfficer > gNationalAvgPeoplePerOfficer
        ? "치안 피로도 높음(대응 지연 가능성 있음)"
        : "치안 집중도 높음(치안 대응 여건이 비교적 양호함)";

    snprintf(out, outSize,
        "\n[%s] 치안 인프라 통계 현황\n"
        "============================================================\n"
        "[요약]\n"
        "- 경찰 정원                 : %d명\n"
        "- 관할 인구                 : %d명\n"
        "- 경찰관 1인당 담당 인구수  : %d명\n"
        "- 전국 평균 담당 인구수     : %.1f명\n"
        "- 평균 대비 부담 비율       : %.2f배\n"
        "- 치안 서비스 대응력 지수   : %s\n"
        "------------------------------------------------------------\n"
        "※ 담당 인구수가 전국 평균보다 높으면 경찰관 1명의\n"
        "   업무 부담이 상대적으로 큰 것으로 해석합니다.",
        police.name, police.officerCount, police.population, police.popPerOfficer,
        gNationalAvgPeoplePerOfficer, ratio, status);
}

/* 대표 범죄 유형에 맞는 사용자 행동 가이드 문장을 반환함 */
static const char* GetCrimeGuide(const char* crimeName) {
    if (!crimeName) return "기본 생활 안전수칙을 지키고 위험 상황은 112에 신고하세요.";

    if (strstr(crimeName, "사기")) {
        return "문자 링크, 택배/검찰/금융기관 사칭 전화, 계좌 이체 요구를 바로 믿지 말고 공식 앱이나 대표번호로 재확인하세요.";
    }
    if (strstr(crimeName, "절도")) {
        return "외출 전 현관과 창문 잠금 상태를 확인하고, 차량과 자전거 및 무인택배함에는 귀중품을 오래 두지 마세요.";
    }
    if (strstr(crimeName, "교통")) {
        return "출퇴근 시간대와 야간 보행 시 횡단보도와 이면도로를 특히 주의하고, 음주운전 의심 차량은 즉시 신고하세요.";
    }
    if (strstr(crimeName, "폭력") || strstr(crimeName, "폭행") || strstr(crimeName, "상해") ||
        strstr(crimeName, "협박") || strstr(crimeName, "손괴")) {
        return "심야 시간대 유흥가와 좁은 골목 통행을 줄이고, 시비 상황은 대응보다 거리 확보와 신고를 우선하세요.";
    }
    if (strstr(crimeName, "강간") || strstr(crimeName, "강제추행") || strstr(crimeName, "성풍속")) {
        return "늦은 시간 혼자 이동할 때 밝은 길을 이용하고, 불안한 상황에서는 위치 공유와 안전귀가 서비스를 활용하세요.";
    }
    if (strstr(crimeName, "강도") || strstr(crimeName, "살인") || strstr(crimeName, "방화") ||
        strstr(crimeName, "강력")) {
        return "위험 신호가 보이면 즉시 사람이 많은 곳으로 이동하고, 직접 제압보다 112 신고와 주변 도움 요청을 우선하세요.";
    }
    if (strstr(crimeName, "횡령") || strstr(crimeName, "배임") || strstr(crimeName, "특별경제")) {
        return "금전 거래와 계약은 증빙을 남기고, 개인 계좌 입금 요구나 비공식 투자 권유는 가족이나 기관과 재확인하세요.";
    }
    if (strstr(crimeName, "마약")) {
        return "출처가 불분명한 약물, 음료, 택배 수령을 거절하고, 관련 권유나 의심 장소는 가까운 경찰관서에 신고하세요.";
    }
    if (strstr(crimeName, "도박")) {
        return "불법 도박 사이트 링크와 고수익 보장 홍보를 차단하고, 청소년 또는 가족 피해가 의심되면 상담기관 도움을 받으세요.";
    }
    if (strstr(crimeName, "보건")) {
        return "불법 의약품, 무허가 시술, 가짜 건강식품 거래를 피하고, 의심 업체는 식약처 또는 관할 기관에 확인하세요.";
    }
    if (strstr(crimeName, "선거")) {
        return "금품 제공, 허위사실 유포, 개인정보를 요구하는 선거 연락은 선관위 안내와 공식 채널로 확인하세요.";
    }
    if (strstr(crimeName, "병역")) {
        return "병역 관련 서류와 개인정보는 공식 병무청 채널에서만 처리하고, 대리 처리와 금전 요구는 거절하세요.";
    }
    if (strstr(crimeName, "환경")) {
        return "폐기물 무단투기와 오염 행위 발견 시 위치와 시간을 기록해 지자체 또는 경찰에 신고하세요.";
    }
    if (strstr(crimeName, "기타")) {
        return "기타 범죄 비중이 높으므로 생활권 주변의 반복 민원과 위험 장소를 기록하고 지자체 또는 경찰 신고 채널을 활용하세요.";
    }
    if (strstr(crimeName, "지능")) {
        return "개인정보, 인증번호, 금융정보 요구에 응답하지 말고 의심 메시지는 삭제 전 캡처해 신고 자료로 보관하세요.";
    }

    return "주요 생활권의 조명, CCTV, 귀가 동선을 확인하고 위험 상황은 직접 해결하려 하지 말고 신고하세요.";
}

/* 실질 치안 위험도와 맞춤형 가이드라인 결과 문자열을 생성함 */
static void BuildRiskAndGuide(int regionIndex, char* out, int outSize) {
    CrimeRank list[MAX_CRIME_ROWS];
    CrimeNode* c = gCrimes;
    PoliceSummary police;
    int count = 0;
    int used = 0;
    int provinceIndex = ProvinceIndexFromRegion(regionIndex);
    long long total = GetRegionCrimeTotal(regionIndex);
    double crimeRatio = gNationalAvgCrime > 0 ? (double)total / gNationalAvgCrime : 0.0;
    double policeRatio;
    double risk;
    const char* label = "낮음";
    const char* comment = "범죄 발생과 치안 인프라를 함께 볼 때 비교적 안정적인 편입니다.";
    const char* action = "기본 생활 안전수칙을 유지하고, 자주 이동하는 생활권의 위험 지점을 확인하세요.";

    while (c && count < MAX_CRIME_ROWS) {
        snprintf(list[count].name, sizeof(list[count].name), "%s - %s", c->majorType, c->minorType);
        list[count].count = c->counts[regionIndex];
        count++;
        c = c->next;
    }
    SortCrimeRanks(list, count);

    if (!GetPoliceSummaryByProvince(provinceIndex, &police)) {
        snprintf(out, outSize, "해당 지역의 도/시 경찰 인프라 정보를 찾을 수 없습니다.");
        return;
    }

    policeRatio = gNationalAvgPeoplePerOfficer > 0 ? (double)police.popPerOfficer / gNationalAvgPeoplePerOfficer : 0.0;
    risk = crimeRatio * policeRatio;

    if (risk >= 1.40) {
        label = "높음";
        comment = "범죄 발생률에 비해 치안 인프라 부담이 커 최우선 주의가 필요한 지역입니다.";
        action = "야간 이동 동선을 짧고 밝은 길 위주로 조정하고, 반복적으로 불안한 장소는 112 또는 지자체 안전신문고에 기록 신고하세요.";
    } else if (risk >= 0.90) {
        label = "보통";
        comment = "일상적인 주의가 필요한 수준입니다.";
        action = "주요 범죄 유형에 맞춰 개인 예방수칙을 강화하고, 귀가 시간과 이동 경로를 가족이나 지인과 공유하세요.";
    }

    AppendFormat(out, outSize, &used,
        "\n[%s] 실질 치안 위험도와 맞춤형 치안 가이드라인\n"
        "============================================================\n"
        "[위험도 요약]\n"
        "- 지역 총 범죄 발생 건수    : %lld건\n"
        "- 전국 지역 평균 범죄 건수  : %.1f건\n"
        "- 범죄 비율                 : %.2f배\n"
        "- 적용 경찰 인프라 지역     : %s\n"
        "- 경찰 인프라 부담 비율     : %.2f배\n"
        "- 실질 치안 위험도          : %.2f\n"
        "- 위험도 평가               : %s\n"
        "- 해석                      : %s\n"
        "------------------------------------------------------------\n"
        "[계산식]\n"
        "실질위험도 = 지역범죄건수/전국평균범죄건수\n"
        "           * 지역담당인구/전국평균담당인구\n"
        "※ 범죄 통계는 시/군/구 단위, 경찰 인프라 통계는 도/시\n"
        "   단위이므로 선택 지역의 상위 도/시 경찰 값을 적용합니다.\n"
        "------------------------------------------------------------\n"
        "[우선 행동 안내]\n"
        "- %s\n"
        "------------------------------------------------------------\n"
        "[주요 범죄 유형별 맞춤 가이드]\n",
        gRegions[regionIndex].regionName, total, gNationalAvgCrime, crimeRatio,
        police.name, policeRatio, risk, label, comment, action);

    AppendFormat(out, outSize, &used,
        "1. %s (%d건)\n   - %s\n",
        list[0].name, list[0].count, GetCrimeGuide(list[0].name));
    AppendFormat(out, outSize, &used,
        "2. %s (%d건)\n   - %s\n",
        list[1].name, list[1].count, GetCrimeGuide(list[1].name));
    AppendFormat(out, outSize, &used,
        "3. %s (%d건)\n   - %s\n",
        list[2].name, list[2].count, GetCrimeGuide(list[2].name));

    AppendText(out, outSize, &used,
        "------------------------------------------------------------\n"
        "[공통 지침]\n"
        "- 위험 상황은 직접 해결하려 하지 말고 112에 신고하세요.\n"
        "- 반복적으로 불안한 장소는 시간, 위치, 상황을 기록해\n"
        "  경찰 또는 지자체 민원 채널에 전달하세요.");
}

/* 정상 처리 결과를 공통 응답 패킷으로 전송함 */
static void SendText(SOCKET sock, const char* text) {
    SendPacket(sock, PKT_RES_TEXT, text ? text : "");
}

/* 오류 안내 결과를 공통 오류 패킷으로 전송함 */
static void SendError(SOCKET sock, const char* text) {
    SendPacket(sock, PKT_ERROR_RES, text ? text : "");
}

/* 클라이언트 요청 타입에 따라 로그인, 회원가입, 목록 조회, 통계 분석을 분기 처리함 */
static void HandleClientRequest(SOCKET sock, PacketHeader hdr, char* payload) {
    char res[BIG_BUF_SIZE];

    if (hdr.type == PKT_LOGIN_REQ) {
        char* id = strtok(payload, "\t");
        char* pw = strtok(NULL, "\t");
        UserNode* user = id ? FindUserById(id) : NULL;

        if (user && pw && strcmp(user->info.pw, pw) == 0) {
            ClientNode* curr;
            WaitForSingleObject(gMutex, INFINITE);
            curr = gClients;
            while (curr) {
                if (curr->sock == sock) {
                    strncpy(curr->id, id, NAME_SIZE - 1);
                    break;
                }
                curr = curr->next;
            }
            ReleaseMutex(gMutex);
            printf("[로그인] %s\n", id);
            SendPacket(sock, PKT_LOGIN_RES, "1");
        } else {
            SendPacket(sock, PKT_LOGIN_RES, "0");
        }
        return;
    }

    if (hdr.type == PKT_REGISTER_REQ) {
        UserInfo user;
        UserNode* node;
        char* id = strtok(payload, "\t");
        char* pw = strtok(NULL, "\t");
        char* age = strtok(NULL, "\t");
        char* region = strtok(NULL, "\t");

        if (!id || !pw || !age || !region) {
            SendError(sock, "회원가입 입력값이 부족합니다.");
            return;
        }
        if (FindUserById(id)) {
            SendError(sock, "이미 사용 중인 아이디입니다.");
            return;
        }

        memset(&user, 0, sizeof(user));
        strncpy(user.id, id, NAME_SIZE - 1);
        strncpy(user.pw, pw, NAME_SIZE - 1);
        user.age = atoi(age);
        strncpy(user.region, region, REGION_SIZE - 1);
        CleanText(user.region);

        if (AppendUserToFile(&user) != 0) {
            SendError(sock, "회원정보 저장에 실패했습니다.");
            return;
        }

        node = (UserNode*)calloc(1, sizeof(UserNode));
        if (node) {
            node->info = user;
            node->next = gUsers;
            gUsers = node;
        }
        snprintf(res, sizeof(res), "'%s' 계정이 등록되었습니다. 로그인해서 이용하세요.", user.id);
        SendText(sock, res);
        return;
    }

    if (hdr.type == PKT_REQ_PROVINCE_LIST) {
        BuildProvinceList(res, sizeof(res));
        SendText(sock, res);
        return;
    }

    if (hdr.type == PKT_REQ_CITY_LIST) {
        BuildCityList(atoi(payload), res, sizeof(res));
        SendText(sock, res);
        return;
    }

    if (hdr.type == PKT_REQ_01_CRIME_TOP3 || hdr.type == PKT_REQ_02_SAFETY_GRADE) {
        int regionIndex = ResolveRegionSelection(payload);
        if (regionIndex < 0) {
            SendError(sock, "선택한 시/군/구 번호가 올바르지 않습니다.");
            return;
        }
        BuildCrimeAndSafety(regionIndex, res, sizeof(res));
        SendText(sock, res);
        return;
    }

    if (hdr.type == PKT_REQ_03_POLICE_COUNT || hdr.type == PKT_REQ_04_SECURITY_IDX) {
        int provinceIndex = atoi(payload);
        BuildPoliceAndResponse(provinceIndex, res, sizeof(res));
        SendText(sock, res);
        return;
    }

    if (hdr.type == PKT_REQ_05_REAL_RISK || hdr.type == PKT_REQ_06_GUIDELINE) {
        int regionIndex = ResolveRegionSelection(payload);
        if (regionIndex < 0) {
            SendError(sock, "선택한 시/군/구 번호가 올바르지 않습니다.");
            return;
        }
        BuildRiskAndGuide(regionIndex, res, sizeof(res));
        SendText(sock, res);
        return;
    }

    SendError(sock, "지원하지 않는 요청입니다.");
}

static void CleanupResources(void) {
    while (gClients) {
        ClientNode* next = gClients->next;
        closesocket(gClients->sock);
        free(gClients);
        gClients = next;
    }
    while (gUsers) {
        UserNode* next = gUsers->next;
        free(gUsers);
        gUsers = next;
    }
    while (gCrimes) {
        CrimeNode* next = gCrimes->next;
        free(gCrimes);
        gCrimes = next;
    }
    while (gPolice) {
        PoliceNode* next = gPolice->next;
        free(gPolice);
        gPolice = next;
    }
}