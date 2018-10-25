#include <ntifs.h>
#include "TypeOverwriteMitigation.h"
#include "PoolSliderMitigation.h"
#include "PoolBloaterMitigation.h"
#include "FailUnsignedDriverLoad.h"
#include "Config.h"

extern "C" {
    DRIVER_INITIALIZE DriverEntry;
}

static
VOID
CreateProcessNotifyEx(
    _Inout_   PEPROCESS Process,
    _In_      HANDLE ProcessId,
    _In_opt_  PPS_CREATE_NOTIFY_INFO pCreateInfo
)
{
    PAGED_CODE();

#if USE_TYPE_INDEX_OVERWRITE_MITIGATION && defined(_AMD64_)
    if (pCreateInfo == nullptr) {
        // The process is being terminated.
        return;
    }

    NTSTATUS status = MitigateObjectTypeOverwrite(ProcessId, Process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to harden process %u against object type overwrite attack\n", HandleToULong(ProcessId));
    }
#else // _X86_
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(pCreateInfo);
#endif // USE_TYPE_INDEX_OVERWRITE_MITIGATION && defined(_AMD64_)

}

static
VOID
LoadImageNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
#if USE_POOL_BLOATER_MITIGATION
    PoolBloaterLoadImageNotify(FullImageName, ProcessId, ImageInfo);
#elif USE_POOL_SLIDER_MITIGATION
    PoolSliderLoadImageNotify(FullImageName, ProcessId, ImageInfo);
#endif // USE_POOL_BLOATER_MITIGATION
}

VOID
Unload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotify_FailUnsignedDriverLoad);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);

    SYSTEM_CODEINTEGRITY_INFORMATION codeIntegrityInfo{};

    if (MmIsDriverVerifying(DriverObject)) {
        DbgPrint("*** WARNING: SKREAM might be incompatible with driver verifier! ***\n");
    }

    DriverObject->DriverUnload = Unload;

    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to register process creation notify routine, status = %08x\n", status);
        goto Exit;
    }

    status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to register load image notify routine, status = %08x\n", status);
        goto Exit;
    }
	
	//
    // Check current code integrity options.
    //
    
    codeIntegrityInfo.Length = sizeof(codeIntegrityInfo);
    ULONG returnedLength = 0;
    status = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &codeIntegrityInfo, sizeof(codeIntegrityInfo), &returnedLength);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to query system information.");
        goto Exit;
    }

    DbgPrint("CodeIntegrityOptions = 0x%x\n", codeIntegrityInfo.CodeIntegrityOptions);

    if(FlagOn(codeIntegrityInfo.CodeIntegrityOptions, CODEINTEGRITY_OPTION_ENABLED))
    {
        //
        // DSE is enabled - register our callback and block any unsigned driver from loading.
        // If DSE is disabled when we start, there is no need to enable our mitigation.
        //
        status = PsSetLoadImageNotifyRoutine(LoadImageNotify_FailUnsignedDriverLoad);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to register load image notify callback for failing unsigned drivers load");
            goto Exit;
        }
    }

    DbgPrint("SKREAM was successfully loaded!\n");

Exit:
    if (!NT_SUCCESS(status)) {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
    }

    return status;
}
