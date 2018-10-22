#include <ntifs.h>
#include <ntimage.h>
#include <fltKernel.h>
#include <windef.h>

static NTSTATUS FailDriverLoad(_In_ PVOID ImageBase, _In_ NTSTATUS FailureCode)
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

void LoadImageNotify_FailUnsignedDriverLoad(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    if(ImageInfo->ImageSignatureLevel == SE_SIGNING_LEVEL_UNSIGNED)
    {
        // Block driver load
        NTSTATUS status = FailDriverLoad(ImageInfo->ImageBase, STATUS_ACCESS_DENIED);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Did not manage to fail driver %s from loading", FullImageName);
        }
        else {
            DbgPrint("Failed loading of driver %s", FullImageName);
        }
    }
}