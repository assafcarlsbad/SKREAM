#pragma once

#include <ntifs.h>

NTSTATUS InitializeUnsignedDriverLoadMitigation();
VOID UninitializeUnsignedDriverLoadMitigation();