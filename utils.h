#ifndef UTILS_H
#define UTILS_H

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <intrin.h>
#include <stdint.h>
#include <Library/BaseMemoryLib.h>

typedef EFI_STATUS(EFIAPI* IMAGE_CALLBACK)(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable
);

void remove_hook(
    void* target,
    UINT8 backup[12]
);

void hook_jmp64_indirect(
    void* target,
    void* hook,
    UINT8 backup[12]
);

void* signature_scan(
    uintptr_t start,
    uintptr_t end,
    const char* pattern
);

EFI_STATUS
EFIAPI
ConvertImageMemoryType(
    EFI_ALLOCATE_TYPE Type,
    EFI_MEMORY_TYPE MemoryType,
    IMAGE_CALLBACK Callback,
    EFI_HANDLE ImageHandle
);

#endif
