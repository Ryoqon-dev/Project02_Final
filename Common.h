// 프로젝트명 : 당신의 지역은 괜찮아요? (Is it safe around where you LIVE?)
// 파일명 : Common.h
/*  설명  : 클라이언트와 서버 간의 통신을 위한 공통 정의 */
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

/* 서버와 클라이언트가 함께 사용하는 기본 크기와 포트를 정의함 */
#define PORT 9000
#define MAX_CLIENTS 100
#define BUF_SIZE 4096
#define BIG_BUF_SIZE 32768
#define NAME_SIZE 64
#define REGION_SIZE 128
#define MAX_REGIONS 300
#define MAX_CRIME_ROWS 1000

/*
    통신 프로토콜 약속을 정의함
    모든 메시지는 PacketHeader를 먼저 보내고 payload_len만큼 문자열 Payload를 이어서 보냄
    Payload 문자열은 UTF-8 기준으로 전송하며 여러 값은 탭 문자('\t')로 구분함

    PKT_LOGIN_REQ          : "id\tpw"를 서버로 전송한다.
    PKT_LOGIN_RES          : 서버가 "1" 또는 "0"을 응답한다.
    PKT_REGISTER_REQ       : "id\tpw\tage\tregion"을 서버로 전송한다.
    PKT_REQ_PROVINCE_LIST  : 빈 Payload로 도/시 목록을 요청한다.
    PKT_REQ_CITY_LIST      : "provinceIndex"로 시/군/구 목록을 요청한다.
    PKT_REQ_01_CRIME_TOP3  : "provinceIndex\tcityIndex"로 범죄 통계 현황을 요청한다.
    PKT_REQ_02_SAFETY_GRADE: "provinceIndex\tcityIndex"로 안전 등급을 요청한다.
    PKT_REQ_03_POLICE_COUNT: "provinceIndex"로 경찰 인프라 통계를 요청한다.
    PKT_REQ_04_SECURITY_IDX: "provinceIndex"로 대응력 지수를 요청한다.
    PKT_REQ_05_REAL_RISK   : "provinceIndex\tcityIndex"로 실질 위험도를 요청한다.
    PKT_REQ_06_GUIDELINE   : "provinceIndex\tcityIndex"로 맞춤형 가이드라인을 요청한다.
    PKT_RES_TEXT           : 서버가 정상 처리 결과 문자열을 응답한다.
    PKT_ERROR_RES          : 서버가 오류 안내 문자열을 응답한다.
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

typedef struct {
    PacketType type;
    int payload_len;
} PacketHeader;

typedef struct {
    char id[NAME_SIZE];
    char pw[NAME_SIZE];
    int age;
    char region[REGION_SIZE];
} UserInfo;

typedef struct CrimeNode {
    char majorType[REGION_SIZE];
    char minorType[REGION_SIZE];
    int counts[MAX_REGIONS];
    struct CrimeNode* next;
} CrimeNode;

typedef struct PoliceNode {
    char regionName[REGION_SIZE];
    int officerCount;
    int population;
    int popPerOfficer;
    struct PoliceNode* next;
} PoliceNode;

typedef struct ClientNode {
    SOCKET sock;
    char id[NAME_SIZE];
    struct ClientNode* next;
} ClientNode;

typedef struct {
    char inputName[REGION_SIZE];
    char officialName[REGION_SIZE];
} RegionMapping;

/* 지정한 길이만큼 데이터가 모두 전송될 때까지 send를 반복함 */
static int SendAll(SOCKET sock, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int ret = send(sock, data + sent, len - sent, 0);
        if (ret <= 0) return -1;
        sent += ret;
    }
    return 0;
}

/* 지정한 길이만큼 데이터가 모두 수신될 때까지 recv를 반복함 */
static int RecvAll(SOCKET sock, char* data, int len) {
    int received = 0;
    while (received < len) {
        int ret = recv(sock, data + received, len - received, 0);
        if (ret <= 0) return -1;
        received += ret;
    }
    return 0;
}

/* 공통 PacketHeader와 Payload를 하나의 논리 패킷으로 전송함 */
static int SendPacket(SOCKET sock, PacketType type, const char* payload) {
    PacketHeader hdr;
    hdr.type = type;
    hdr.payload_len = payload ? (int)strlen(payload) : 0;

    if (SendAll(sock, (const char*)&hdr, sizeof(hdr)) != 0) return -1;
    if (hdr.payload_len > 0 && SendAll(sock, payload, hdr.payload_len) != 0) return -1;
    return 0;
}

/* 공통 PacketHeader를 읽은 뒤 payload_len만큼 Payload를 안전하게 수신함 */
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
