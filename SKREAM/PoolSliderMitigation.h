#pragma once

#include <ntifs.h>
#include <minwindef.h>



VOID
PoolSliderLoadImageNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);
