// 프로젝트명 : 당신의 지역은 괜찮아요? (Is it safe around where you LIVE?)
// 파일명 : Common.h
/*  설명  : 클라이언트와 서버가 함께 사용하는 통신 규칙, 자료구조, 송수신 함수를 정의하는 역할 */
// 작성자 : 2023243047 박교범
// 작성일 : 2026-05-25 ~ 2026-06-15

#ifndef COMMON_H
#define COMMON_H

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

// [네트워크 상수] 서버 접속 포트와 송수신 버퍼 크기를 정해 두는 부분
#define PORT 9000
#define MAX_CLIENTS 100
#define BUF_SIZE 4096
#define BIG_BUF_SIZE 32768
#define NAME_SIZE 64
#define REGION_SIZE 128
#define MAX_REGIONS 300
#define MAX_CRIME_ROWS 1000

/*
[패킷 타입 목록] 클라이언트와 서버가 요청과 응답을 구분할 때 사용하는 메시지 번호 모음
모든 메시지는 PacketHeader를 먼저 보내고 payload_len만큼 문자열 Payload를 이어서 보냄
Payload 문자열은 UTF-8 기준으로 전송하며 여러 값은 탭 문자('\t')로 구분함
    PKT_LOGIN_REQ          : "id\tpw"를 서버로 전송하는 로그인 요청 메시지
    PKT_LOGIN_RES          : 서버가 "1" 또는 "0"으로 로그인 성공 여부를 응답하는 메시지
    PKT_REGISTER_REQ       : "id\tpw\tage\tregion"을 서버로 전송하는 회원가입 요청 메시지
    PKT_REQ_PROVINCE_LIST  : 빈 Payload로 도/시 목록을 요청하는 메시지
    PKT_REQ_CITY_LIST      : "provinceIndex"로 시/군/구 목록을 요청하는 메시지
    PKT_REQ_01_CRIME_TOP3  : "provinceIndex\tcityIndex"로 범죄 통계 현황을 요청하는 메시지
    PKT_REQ_02_SAFETY_GRADE: "provinceIndex\tcityIndex"로 안전 등급을 요청하는 메시지
    PKT_REQ_03_POLICE_COUNT: "provinceIndex"로 경찰 인프라 통계를 요청하는 메시지
    PKT_REQ_04_SECURITY_IDX: "provinceIndex"로 대응력 지수를 요청하는 메시지
    PKT_REQ_05_REAL_RISK   : "provinceIndex\tcityIndex"로 실질 위험도를 요청하는 메시지
    PKT_REQ_06_GUIDELINE   : "provinceIndex\tcityIndex"로 맞춤형 가이드라인을 요청하는 메시지
    PKT_RES_TEXT           : 서버가 정상 처리 결과 문자열을 응답하는 메시지
    PKT_ERROR_RES          : 서버가 오류 안내 문자열을 응답하는 메시지
*/
typedef enum {
    PKT_LOGIN_REQ = 1,
    PKT_LOGIN_RES,
    PKT_REGISTER_REQ,
    PKT_REQ_PROVINCE_LIST,
    PKT_REQ_CITY_LIST,
    PKT_REQ_01_CRIME_TOP3,
    PKT_REQ_02_SAFETY_GRADE,
    PKT_REQ_03_POLICE_COUNT,
    PKT_REQ_04_SECURITY_IDX,
    PKT_REQ_05_REAL_RISK,
    PKT_REQ_06_GUIDELINE,
    PKT_RES_TEXT,
    PKT_ERROR_RES
} PacketType;

// [패킷 헤더 구조체] 메시지 종류와 Payload 길이를 먼저 알려주는 역할
typedef struct {
    PacketType type;      // 메시지 타입을 구분하는 값
    int payload_len;      // 뒤에 이어지는 Payload 문자열 길이
} PacketHeader;

// [사용자 정보 구조체] 회원가입과 로그인에 필요한 계정 정보를 묶어 저장하는 역할
typedef struct {
    char id[NAME_SIZE];           // 사용자 아이디
    char pw[NAME_SIZE];           // 사용자 비밀번호
    int age;                      // 사용자 나이
    char region[REGION_SIZE];     // 사용자 거주 지역명
} UserInfo;

// [범죄 통계 노드] 범죄 유형 하나와 지역별 발생 건수를 연결 리스트로 관리하는 역할
typedef struct CrimeNode {
    char majorType[REGION_SIZE];          // 범죄 대분류명
    char minorType[REGION_SIZE];          // 범죄 소분류명
    int counts[MAX_REGIONS];              // 지역별 범죄 발생 건수 배열
    struct CrimeNode* next;               // 다음 범죄 통계 노드 주소
} CrimeNode;

// [경찰 통계 노드] 지역별 경찰관 수와 담당 인구 정보를 연결 리스트로 관리하는 역할
typedef struct PoliceNode {
    char regionName[REGION_SIZE];         // 경찰 통계 지역명
    int officerCount;                     // 경찰관 수
    int population;                       // 담당 인구수
    int popPerOfficer;                    // 경찰관 1인당 담당 인구수
    struct PoliceNode* next;              // 다음 경찰 통계 노드 주소
} PoliceNode;

// [접속자 노드] 현재 서버에 연결된 클라이언트 소켓과 사용자 아이디를 관리하는 역할
typedef struct ClientNode {
    SOCKET sock;                  // 클라이언트와 연결된 소켓
    char id[NAME_SIZE];           // 접속한 사용자 아이디
    struct ClientNode* next;      // 다음 클라이언트 노드 주소
} ClientNode;

// [지역명 매핑 구조체] 사용자 입력 지역명과 CSV 기준 공식 지역명을 연결하는 역할
typedef struct {
    char inputName[REGION_SIZE];      // 사용자가 입력한 지역명
    char officialName[REGION_SIZE];   // CSV 데이터와 비교할 공식 지역명
} RegionMapping;

// [전체 바이트 송신] 지정한 길이의 데이터가 모두 보내질 때까지 send를 반복하는 함수
static int SendAll(SOCKET sock, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int ret = send(sock, data + sent, len - sent, 0);
        if (ret <= 0) return -1;
        sent += ret;
    }
    return 0;
}

// [전체 바이트 수신] 지정한 길이의 데이터가 모두 들어올 때까지 recv를 반복하는 함수
static int RecvAll(SOCKET sock, char* data, int len) {
    int received = 0;
    while (received < len) {
        int ret = recv(sock, data + received, len - received, 0);
        if (ret <= 0) return -1;
        received += ret;
    }
    return 0;
}

// [패킷 조립 송신] PacketHeader와 Payload를 순서대로 묶어 전송하는 함수
static int SendPacket(SOCKET sock, PacketType type, const char* payload) {
    PacketHeader hdr;
    hdr.type = type;
    hdr.payload_len = payload ? (int)strlen(payload) : 0;

    if (SendAll(sock, (const char*)&hdr, sizeof(hdr)) != 0) return -1;
    if (hdr.payload_len > 0 && SendAll(sock, payload, hdr.payload_len) != 0) return -1;
    return 0;
}

// [패킷 해석 수신] PacketHeader를 먼저 읽고 payload_len만큼 Payload를 받아오는 함수
static int RecvPacket(SOCKET sock, PacketHeader* hdr, char* payload, int payloadCap) {
    if (RecvAll(sock, (char*)hdr, sizeof(*hdr)) != 0) return -1;
    if (hdr->payload_len < 0 || hdr->payload_len >= payloadCap) return -1;

    if (hdr->payload_len > 0) {
        if (RecvAll(sock, payload, hdr->payload_len) != 0) return -1;
        payload[hdr->payload_len] = '\0';
    } else {
        payload[0] = '\0';
    }
    return 0;
}

#endif
