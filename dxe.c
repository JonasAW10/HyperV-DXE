#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Library/DevicePathLib.h>
#include <intrin.h>
#include <stdint.h>
#include <Protocol/MpService.h>
#include <Register/Intel/Msr.h>
#include <Library/BaseMemoryLib.h>

#define HOOK_SIZE 12

typedef uint32_t ULONG;
typedef uint16_t USHORT;
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    CHAR16* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;          // 0x00
    VOID* ExceptionTable;                 // 0x10
    ULONG ExceptionTableSize;             // 0x18
    VOID* GpValue;                        // 0x20
    VOID* NonPagedDebugInfo;              // 0x28
    VOID* DllBase;                        // 0x30
    VOID* EntryPoint;                     // 0x38
    ULONG SizeOfImage;                    // 0x40
    UNICODE_STRING FullDllName;           // 0x48
    UNICODE_STRING BaseDllName;           // 0x58
    ULONG Flags;                          // 0x68
    USHORT LoadCount;                     // 0x6C
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef PKLDR_DATA_TABLE_ENTRY* PPKLDR_DATA_TABLE_ENTRY;

typedef void(__fastcall* hv_launch_t)(
    int64_t hyperv_cr3,
    int64_t hyperv_entry_point,
    int64_t entry_point_gadget,
    uint64_t guest_kernel_cr3
    );


typedef uint64_t(*BlLdrLoadImage_t)(
    int32_t  arg1,
    CHAR16* ModulePath,
    CHAR16* ModuleName,
    void* arg4,
    int64_t  arg5,
    int32_t  arg6,
    int32_t  arg7,
    LIST_ENTRY* arg8,
    PPKLDR_DATA_TABLE_ENTRY  arg9,
    int64_t  arg10,
    int32_t  arg11,
    int32_t  arg12,
    int32_t  arg13,
    int32_t  arg14,
    int32_t  arg15,
    int64_t  arg16,
    int64_t  arg17
    );


typedef EFI_STATUS(EFIAPI* ImgArchStartBootApplication_t)(
    VOID* AppEntry,
    VOID* ImageBase,
    UINTN ImageSize,
    UINT32 BootOption,
    VOID* ReturnArgs
    );


typedef EFI_STATUS(EFIAPI* IMAGE_CALLBACK)(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable
    );


// Update the signature

// C:\windows\system32\hvloader.dll
static const char* hv_launch_signature = "48 53 55 56 57 41 54 41 55 41 56 41 57 48 83 ec 08 48 89 25";

// C:\windows\system32\winload.efi
static const char* BlLdrLoadImage_signature =
"48 8b c4 48 89 58 08 48"
"89 70 10 48 89 78 18 55"
"48 8d 68 f1 48 81 ec c0"
"00 00 00 8b f1 c6 45 d7"
"00 49 8b c1 48 8d 4d d7";

// SYSTEM partition: \EFI\Microsoft\Boot\bootmgfw.efi
static const char* ImgArchStartBootApplication_signature =
"48 8b c4 48 89 58 20 44 89 40 18 48 89 50 10 48"
"89 48 08 55 56 57 41 54 41 55 41 56 41 57 48 8d"
"68 a9 48 81 ec c0 00 00";


EFI_PHYSICAL_ADDRESS g_relocated_DxeBase;
UINTN g_ImageSize;


VOID* hv_launch_addr = NULL;
VOID* ImgArchStartBootApplication_addr = NULL;
VOID* BlLdrLoadImage_addr = NULL;

UINT8 backup_ImgArchStartBootApplication[HOOK_SIZE];
UINT8 backup_BlLdrLoadImage[HOOK_SIZE];
UINT8 backup_hv_launch[HOOK_SIZE];
EFI_IMAGE_LOAD OrgLoadImage;
STATIC BOOLEAN g_WP;


STATIC
void DisableWriteProtect(void)
{
    UINT64 Cr0 = AsmReadCr0();

    g_WP = (Cr0 & BIT16) != 0;

    if (g_WP)
        AsmWriteCr0(Cr0 & ~BIT16);
}

STATIC
void RestoreWriteProtect(void)
{
    if (g_WP)
        AsmWriteCr0(AsmReadCr0() | BIT16);
}

void remove_hook(void* target, UINT8 backup[12]) {
    DisableWriteProtect();
    UINT8* dst = (UINT8*)target;
    for (int i = 0; i < 12; i++) {
        dst[i] = backup[i];
    }
    RestoreWriteProtect();
}

void hook_jmp64_indirect(void* target, void* hook, uint8_t backup[12])
{
    DisableWriteProtect();
    uint8_t* src = target;
    uint8_t code[12] = {
        0x48, 0xb8,
        0, 0, 0, 0, 0, 0, 0, 0,
        0xff, 0xe0
    };
    uint64_t addr = (uint64_t)hook;

    for (int i = 0; i < 12; i++)
        backup[i] = src[i];

    for (int i = 0; i < 8; i++)
        code[i + 2] = (uint8_t)(addr >> (i * 8));

    for (int i = 0; i < 12; i++)
        src[i] = code[i];
    RestoreWriteProtect();
}


static uint8_t hex_to_byte(const char* s)
{
    uint8_t value = 0;

    for (int i = 0; i < 2; i++) {
        value <<= 4;

        if (s[i] >= '0' && s[i] <= '9')
            value |= s[i] - '0';
        else if (s[i] >= 'A' && s[i] <= 'F')
            value |= s[i] - 'A' + 10;
        else if (s[i] >= 'a' && s[i] <= 'f')
            value |= s[i] - 'a' + 10;
    }

    return value;
}

void* signature_scan(uintptr_t start, uintptr_t end, const char* pattern)
{
    for (uintptr_t addr = start; addr < end; addr++) {

        uintptr_t cur = addr;
        const char* p = pattern;

        while (*p) {

            while (*p == ' ')
                p++;

            if (!*p)
                return (void*)addr;

            if (cur >= end)
                break;

            if (*p == '?') {

                p++;

                if (*p == '?')
                    p++;

            }
            else {

                if (*(uint8_t*)cur != hex_to_byte(p))
                    break;

                p += 2;
            }

            cur++;
        }

        while (*p == ' ')
            p++;

        if (!*p)
            return (void*)addr;
    }

    return NULL;
}



STATIC
VOID __fastcall Hooked_hv_launch(
    int64_t hyperv_cr3,
    int64_t hyperv_entry_point,
    int64_t entry_point_gadget,
    uint64_t guest_kernel_cr3
)
{
    hv_launch_t hv_launch = (hv_launch_t)hv_launch_addr;

    remove_hook(hv_launch_addr, backup_hv_launch);

    // TODO: Scan Hyper-V CR3
    // TODO: Find non-present PML4 entry
    // TODO: Inject image mapping
    // TODO: Modify VM-exit handling

    hv_launch(
        hyperv_cr3,
        hyperv_entry_point,
        entry_point_gadget,
        guest_kernel_cr3
    );
}




STATIC
UINT64
HookedBlLdrLoadImage(
    int32_t  arg1,
    CHAR16* ModulePath,
    CHAR16* ModuleName,
    void* arg4,
    int64_t  arg5,
    int32_t  arg6,
    int32_t  arg7,
    LIST_ENTRY* arg8,
    PPKLDR_DATA_TABLE_ENTRY  arg9,
    int64_t  arg10,
    int32_t  arg11,
    int32_t  arg12,
    int32_t  arg13,
    int32_t  arg14,
    int32_t  arg15,
    int64_t  arg16,
    int64_t  arg17
)
{

    remove_hook(BlLdrLoadImage_addr, backup_BlLdrLoadImage);
    BlLdrLoadImage_t BlLdrLoadImage = (BlLdrLoadImage_t)BlLdrLoadImage_addr;
    EFI_STATUS Status =
        BlLdrLoadImage(
            arg1,
            ModulePath,
            ModuleName,
            arg4,
            arg5,
            arg6,
            arg7,
            arg8,
            arg9,
            arg10,
            arg11,
            arg12,
            arg13,
            arg14,
            arg15,
            arg16,
            arg17
        );

    if (arg9)
    {
        PKLDR_DATA_TABLE_ENTRY TableEntry =
            *(PKLDR_DATA_TABLE_ENTRY*)arg9;

        if (TableEntry &&
            TableEntry->BaseDllName.Buffer &&
            !StrCmp(TableEntry->BaseDllName.Buffer, L"hvloader.dll"))
        {
            uintptr_t start = (uintptr_t)TableEntry->DllBase;
            uintptr_t end = start + TableEntry->SizeOfImage;
            hv_launch_addr = signature_scan(
                start,
                end,
                hv_launch_signature
            );

            if (hv_launch_addr) {
                hook_jmp64_indirect((void*)hv_launch_addr, (void*)Hooked_hv_launch, backup_hv_launch);
            }
        }
    }
    hook_jmp64_indirect((void*)BlLdrLoadImage_addr, (void*)HookedBlLdrLoadImage, backup_BlLdrLoadImage);
    return Status;

}






STATIC
EFI_STATUS
EFIAPI
HookedImgArchStartBootApplication(
    IN VOID* AppEntry,
    IN VOID* ImageBase,
    IN UINTN ImageSize,
    IN UINT32 BootOption,
    IN VOID* ReturnArgs
)
{



    uintptr_t start = (uintptr_t)ImageBase;
    uintptr_t end = (uintptr_t)ImageBase + ImageSize;
    BlLdrLoadImage_addr = signature_scan(start, end, BlLdrLoadImage_signature);


    if (BlLdrLoadImage_addr) {
        gST->ConOut->SetAttribute(gST->ConOut, EFI_RED);
        Print(L"winload!BlLdrLoadImage: 0x%p\r\n", BlLdrLoadImage_addr);
        Print(L"hooking winload!BlLdrLoadImage --> HookedBlLdrLoadImage: 0x%p\r\n", HookedBlLdrLoadImage);
        hook_jmp64_indirect((void*)BlLdrLoadImage_addr, (void*)HookedBlLdrLoadImage, backup_BlLdrLoadImage);

    }

    else {

        Print(L"Signature out of dated\\n");

    }

    remove_hook(ImgArchStartBootApplication_addr, backup_ImgArchStartBootApplication);
    ImgArchStartBootApplication_t ImgArchStartBootApplication = (ImgArchStartBootApplication_t)ImgArchStartBootApplication_addr;
    EFI_STATUS Status = ImgArchStartBootApplication(AppEntry, ImageBase, ImageSize, BootOption, ReturnArgs);
    return Status;
}




EFI_STATUS
EFIAPI
HookedLoadImage(
    IN BOOLEAN BootPolicy,
    IN EFI_HANDLE ParentImageHandle,
    IN EFI_DEVICE_PATH_PROTOCOL* DevicePath OPTIONAL,
    IN VOID* SourceBuffer OPTIONAL,
    IN UINTN SourceSize,
    OUT EFI_HANDLE* ImageHandle
)
{
    EFI_STATUS Status;
    EFI_LOADED_IMAGE_PROTOCOL* LoadedImage = NULL;
    CHAR16* Path = NULL;

    Status = OrgLoadImage(
        BootPolicy,
        ParentImageHandle,
        DevicePath,
        SourceBuffer,
        SourceSize,
        ImageHandle
    );

    if (EFI_ERROR(Status) || ImageHandle == NULL || *ImageHandle == NULL) return Status;

    Status = gBS->HandleProtocol(*ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
    if (EFI_ERROR(Status) || LoadedImage == NULL) return Status;
    if (LoadedImage->FilePath == NULL) return Status;
    Path = ConvertDevicePathToText(LoadedImage->FilePath, TRUE, FALSE);
    if (Path)
    {
        if (StrStr(Path, L"bootmgfw.efi") != NULL ||
            StrStr(Path, L"BOOTMGFW.EFI") != NULL)
        {

            uintptr_t start = (uintptr_t)LoadedImage->ImageBase;
            uintptr_t end = start + LoadedImage->ImageSize;
            ImgArchStartBootApplication_addr = signature_scan(start, end,
                    ImgArchStartBootApplication_signature);

            if (ImgArchStartBootApplication_addr) {
                hook_jmp64_indirect((void*)ImgArchStartBootApplication_addr, (void*)HookedImgArchStartBootApplication, backup_ImgArchStartBootApplication);
                gST->ConOut->SetAttribute(gST->ConOut, EFI_RED);
                Print(L"\r\n\r\n");
                Print(L"========================================\r\n");
                Print(L"          Windows loading...\r\n");
                Print(L"========================================\r\n");
                Print(L"\r\n");
                Print(L"bootmgfw.efi detected\r\n");
                Print(L"Image Base: 0x%p\r\n", LoadedImage->ImageBase);
                Print(L"bootmgfw!ImgArchStartBootApplication: 0x%p\r\n", ImgArchStartBootApplication_addr);
                Print(L"hooking bootmgfw!ImgArchStartBootApplication --> HookedImgArchStartBootApplication: 0x%p\r\n", HookedImgArchStartBootApplication);
                Print(L" \r\n");
                gST->ConOut->SetAttribute(gST->ConOut, EFI_GREEN);
                Print(L"LarpVisor is running\r\n");
                Print(L"Press any key to continue ...\r\n");
                Print(L"\r\n");
                gST->ConOut->SetAttribute(gST->ConOut, EFI_LIGHTGRAY);
            }


            else {

                Print(L"Signature out of dated\\n");
            }
        }
        gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, NULL);
        gBS->FreePool(Path);
    }

    return Status;
}





EFI_STATUS
EFIAPI
ConvertImageMemoryType(
    IN EFI_ALLOCATE_TYPE Type,
    IN EFI_MEMORY_TYPE MemoryType,
    IN IMAGE_CALLBACK Callback,
    IN EFI_HANDLE ImageHandle
)
{
    EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
    EFI_STATUS status;
    
    gBS->HandleProtocol(
        ImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID**)&LoadedImage
    );


    VOID* ImageBase = LoadedImage->ImageBase;
    UINTN ImageSize = LoadedImage->ImageSize;
    g_ImageSize = ImageSize;
    UINTN Pages = EFI_SIZE_TO_PAGES(ImageSize);

    status = gBS->AllocatePages(
    Type,
    MemoryType,
    Pages,
    &g_relocated_DxeBase
);

if (EFI_ERROR(status))
    return status;

    gBS->CopyMem(
        (VOID*)(UINTN)NewBase,
        ImageBase,
        ImageSize
    );

    UINTN Offset = (UINT8*)Callback - (UINT8*)ImageBase;
    IMAGE_CALLBACK NewCallback =
        (IMAGE_CALLBACK)((UINT8*)(UINTN)g_relocated_DxeBase + Offset);

    status = NewCallback(ImageHandle, gST);

    return status;
}




EFI_STATUS
EFIAPI
callback(
    IN EFI_HANDLE         ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
)
{

    OrgLoadImage = gBS->LoadImage;
    gBS->LoadImage = HookedLoadImage;
    return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI
DxeEntryPoint(
    IN EFI_HANDLE         ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
)
{

    if (ImageHandle == NULL || SystemTable == NULL)
        return EFI_INVALID_PARAMETER;

    // Relocate Our Image in runtime memory

    EFI_STATUS Status = ConvertImageMemoryType(
        AllocateAnyPages,
        EfiRuntimeServicesCode,
        callback,
        ImageHandle
    );

    return Status;
}
