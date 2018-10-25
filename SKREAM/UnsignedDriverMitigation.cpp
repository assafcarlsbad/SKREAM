#include <ntifs.h>
#include <fltKernel.h>
#include <windef.h>
#include <ntimage.h>
#include "UnsignedDriverMitigation.h"

#pragma region(Code integrity constants)
#define CODEINTEGRITY_OPTION_ENABLED 0x01
#define CODEINTEGRITY_OPTION_TESTSIGN 0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED 0x04
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED 0x08
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED 0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD 0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD 0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED 0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD 0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED 0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED 0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED 0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED 0x2000
#pragma endregion

#define UNSIGNED_DRIVER_PROBE_SIZE 6

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG  Length;
    ULONG  CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemCodeIntegrityInformation = 103
} SYSTEM_INFORMATION_CLASS;

extern "C"
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_ PULONG ReturnLength OPTIONAL
);


static
NTSTATUS
FailDriverLoad(_In_ PVOID ImageBase, _In_ NTSTATUS FailureCode)
{
    NT_ASSERT(ImageBase != nullptr);
    NT_ASSERT(!NT_SUCCESS(FailureCode));

    NTSTATUS status = STATUS_SUCCESS;
    PMDL pEntryPointMdl = nullptr;
    bool lockedPages = false;
    
    __try {
        auto pDosHeader = static_cast<PIMAGE_DOS_HEADER>(ImageBase);
        auto pNtHeader64 = static_cast<PIMAGE_NT_HEADERS64>(Add2Ptr(pDosHeader, pDosHeader->e_lfanew));
        auto pEntryPoint = Add2Ptr(pDosHeader, pNtHeader64->OptionalHeader.AddressOfEntryPoint);
        auto moduleEnd = Add2Ptr(ImageBase, pNtHeader64->OptionalHeader.SizeOfImage);
        
        if ((pEntryPoint >= moduleEnd) || (pEntryPoint < ImageBase)) {
            DbgPrint("Entry point out of module bounds.");
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        // Make sure there is enough space for our entry point modification code.
        if ((reinterpret_cast<PUCHAR>(ROUND_TO_PAGES(moduleEnd)) -
            reinterpret_cast<PUCHAR>(pEntryPoint)) <= UNSIGNED_DRIVER_PROBE_SIZE)
        {
            DbgPrint("Not enough space for EP patch.");
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        // If the entry point of the driver is in the last page of its memory, we could get out of bounds
        // if we try to probe a whole page when calling MmProbeAndLockPages.
        // We only really need the first 6 bytes in order to write over them, so that's all we'll use.
        pEntryPointMdl = IoAllocateMdl(pEntryPoint, UNSIGNED_DRIVER_PROBE_SIZE, FALSE, FALSE, nullptr);
        if (!pEntryPointMdl) {
            DbgPrint("Could not allocate an MDL for EP patch.");
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // Although the entry point is expected to be in system address space, this still could throw,
        // for example an in-page error.
        __try {
            MmProbeAndLockPages(pEntryPointMdl, KernelMode, IoWriteAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            DbgPrint("Exception while trying to probe and lock the EP pages, status: 0x%08x", status);
            __leave;
        }

        lockedPages = true;

        PVOID pWritableEntryPoint = MmGetSystemAddressForMdlSafe(pEntryPointMdl, NormalPagePriority | MdlMappingNoExecute);
        if (!pWritableEntryPoint) {
            DbgPrint("Failed acquiring a system VA for MDL.");
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        status = MmProtectMdlSystemAddress(pEntryPointMdl, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed protecting the MDL system address, status: 0x%08x", status);
            __leave;
        }

        auto failureCodeBytes = reinterpret_cast<PBYTE>(&FailureCode);
        BYTE retCode[] = {
            // mov eax, FailureCode
            0xB8, failureCodeBytes[0], failureCodeBytes[1], failureCodeBytes[2], failureCodeBytes[3],
            // ret
            0xC3
        };

        RtlCopyMemory(pWritableEntryPoint, retCode, sizeof(retCode));
    }
    __finally {
        if (pEntryPointMdl) {
            if (lockedPages) {
                MmUnlockPages(pEntryPointMdl);
            }

            IoFreeMdl(pEntryPointMdl);
        }
    }

    return status;
}

static
VOID
FailUnsignedDriverLoad(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ProcessId);

    if (!ImageInfo->SystemModeImage) {

        //
        // Ignore user-mode images.
        //

        return;
    }

    if (ImageInfo->ImageSignatureLevel == SE_SIGNING_LEVEL_UNSIGNED) {

        //
        // An unsigned driver got loaded into a system which was previously configured to enforce code integrity checks.
        // This is probably an indication of a DSE bypass exploit, so we should block the driver from loading.
        //

        NTSTATUS status = FailDriverLoad(ImageInfo->ImageBase, STATUS_ACCESS_DENIED);
        if (NT_SUCCESS(status)) {
            DbgPrint("Failed loading of driver %s\n", FullImageName);
        }
        else {
            DbgPrint("Did not manage to fail driver %s from loading\n", FullImageName);
        }
    }
}

NTSTATUS InitializeUnsignedDriverLoadMitigation()
{
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Check current code integrity options.
    //

    SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo{};
    CodeIntegrityInfo.Length = sizeof(CodeIntegrityInfo);

    ULONG ReturnedLength = 0;
    status = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &CodeIntegrityInfo, sizeof(CodeIntegrityInfo), &ReturnedLength);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to query code integrity information, status = 0x%08x\n", status);
        goto Exit;
    }

    DbgPrint("CodeIntegrityOptions = 0x%x\n", CodeIntegrityInfo.CodeIntegrityOptions);

    if (!FlagOn(CodeIntegrityInfo.CodeIntegrityOptions, CODEINTEGRITY_OPTION_ENABLED)) {
        
        //
        // If DSE is disabled when we load, there is no need to enable our mitigation.
        //

        goto Exit;
    }

    if (*KdDebuggerEnabled) {

        //
        // Unless the developer explicitly configured the system to do otherwise, code integrity checks are not
        // performed when the kernel debugger is connected to the target machine. Therefore, is the debugger is enabled
        // we don't want to activate the mitigation.
        //
        // See https://docs.microsoft.com/en-us/windows-hardware/drivers/install/appendix-1--enforcing-kernel-mode-signature-verification-in-kernel-debugging-mode
        // for more details.
        //

        goto Exit;
    }

    //
    // If we got here it means that DSE is enabled and the kernel debugger is not enabled - register our callback to
    // block any unsigned driver from loading.
    //

    status = PsSetLoadImageNotifyRoutine(FailUnsignedDriverLoad);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to register load image notify callback for failing unsigned drivers load\n");
        goto Exit;
    }

Exit:
    return status;
}

VOID UninitializeUnsignedDriverLoadMitigation()
{
    PsRemoveLoadImageNotifyRoutine(FailUnsignedDriverLoad);
}
