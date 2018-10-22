#pragma once

#include <ntifs.h>

#define CODEINTEGRITY_OPTION_ENABLED 0x01

#define UNSIGNED_DRIVER_PROBE_SIZE 6

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG  Length;
    ULONG  CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemCodeIntegrityInformation = 103
} SYSTEM_INFORMATION_CLASS;

extern
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_ PULONG ReturnLength OPTIONAL
);

static void LoadImageNotify_FailUnsignedDriverLoad(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
