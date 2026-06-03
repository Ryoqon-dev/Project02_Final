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

#define PORT 9000
#define MAX_CLIENTS 100
#define BUF_SIZE 4096
#define BIG_BUF_SIZE 32768
#define NAME_SIZE 64
#define REGION_SIZE 128
#define MAX_REGIONS 300
#define MAX_CRIME_ROWS 1000

typedef enum {
    PKT_LOGIN_REQ = 1,
    PKT_LOGIN_RES,
    PKT_REGISTER_REQ,
    PKT_CHAT,
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

static int SendAll(SOCKET sock, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int ret = send(sock, data + sent, len - sent, 0);
        if (ret <= 0) return -1;
        sent += ret;
    }
    return 0;
}

static int RecvAll(SOCKET sock, char* data, int len) {
    int received = 0;
    while (received < len) {
        int ret = recv(sock, data + received, len - received, 0);
        if (ret <= 0) return -1;
        received += ret;
    }
    return 0;
}

static int SendPacket(SOCKET sock, PacketType type, const char* payload) {
    PacketHeader hdr;
    hdr.type = type;
    hdr.payload_len = payload ? (int)strlen(payload) : 0;

    if (SendAll(sock, (const char*)&hdr, sizeof(hdr)) != 0) return -1;
    if (hdr.payload_len > 0 && SendAll(sock, payload, hdr.payload_len) != 0) return -1;
    return 0;
}

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
