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
#include <Library/BaseLib.h>

#define HOOK_SIZE 12



typedef struct _UNICODE_STRING
{
    UINT16 Length;
    UINT16 MaximumLength;
    CHAR16* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;          // 0x00
    VOID* ExceptionTable;                 // 0x10
    UINT32 ExceptionTableSize;             // 0x18
    VOID* GpValue;                        // 0x20
    VOID* NonPagedDebugInfo;              // 0x28
    VOID* DllBase;                        // 0x30
    VOID* EntryPoint;                     // 0x38
    UINT32 SizeOfImage;                    // 0x40
    UNICODE_STRING FullDllName;           // 0x48
    UNICODE_STRING BaseDllName;           // 0x58
    UINT32 Flags;                          // 0x68
    UINT16 LoadCount;                     // 0x6C
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef PKLDR_DATA_TABLE_ENTRY* PPKLDR_DATA_TABLE_ENTRY;
typedef wchar_t WCHAR;


typedef uint64_t(*OslFwpKernelSetupPhase1_t)(
    void* _LOADER_PARAMETER_BLOCK
    );


typedef void(__fastcall* hv_launch_t)(
    int64_t  hyperv_cr3,
    int64_t  hyperv_entry_point,
    int64_t  entry_point_gadget,
    uint64_t guest_kernel_cr3
    );


typedef uint64_t(*BlLdrLoadImage_t)(
    int32_t  Unknown1,
    CHAR16* ModulePath,
    CHAR16* ModuleName,
    void* Unknown4,
    int64_t  Unknown5,
    int32_t  Unknown6,
    int32_t  Unknown7,
    LIST_ENTRY* LoadedModuleList,
    PPKLDR_DATA_TABLE_ENTRY  LoadedModuleEntry,
    int64_t  Unknown10,
    int32_t  Unknown11,
    int32_t  Unknown12,
    int32_t  Unknown13,
    int32_t  Unknown14,
    int32_t  Unknown15,
    int64_t  Unknown16,
    int64_t  Unknown17
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
STATIC  const char* g_hv_launch_signature =
"48 53 55 56 57 41 54 41"
"55 41 56 41 57 48 83 ec"
"08 48 89 25";

// C:\windows\system32\winload.efi
STATIC  const char* g_BlLdrLoadImage_signature =
"48 8b c4 48 89 58 08 48"
"89 70 10 48 89 78 18 55"
"48 8d 68 f1 48 81 ec c0"
"00 00 00 8b f1 c6 45 d7"
"00 49 8b c1 48 8d 4d d7";

// SYSTEM partition: \EFI\Microsoft\Boot\bootmgfw.efi
STATIC  const char* g_ImgArchStartBootApplication_signature =
"48 8b c4 48 89 58 20 44 89 40 18 48 89 50 10 48"
"89 48 08 55 56 57 41 54 41 55 41 56 41 57 48 8d"
"68 a9 48 81 ec c0 00 00";


STATIC const char* g_OslFwpKernelSetupPhase1_signature =
"48 89 4c 24 08 55 53 56"
"57 41 54 41 55 41 56 41"
"57 48 8d 6c 24 e1 48 81"
"ec 98 00 00 00 45 33 ed";

EFI_PHYSICAL_ADDRESS g_relocated_DxeBase;
UINTN g_ImageSize;

VOID* g_hv_launch_addr = NULL;
VOID* g_ImgArchStartBootApplication_addr = NULL;
VOID* g_BlLdrLoadImage_addr = NULL;
VOID* g_OslFwpKernelSetupPhase1_addr = NULL;
UINT8 g_backup_OslFwpKernelSetupPhase1[HOOK_SIZE];
UINT8 g_backup_ImgArchStartBootApplication[HOOK_SIZE];
UINT8 g_backup_BlLdrLoadImage[HOOK_SIZE];
UINT8 g_backup_hv_launch[HOOK_SIZE];
EFI_IMAGE_LOAD g_OriginalLoadImage;
EFI_EXIT_BOOT_SERVICES g_OriginalExitBootServices;
STATIC BOOLEAN g_WP;
UINT64 g_ntoskrnl_base_va;
EFI_PHYSICAL_ADDRESS g_ntoskrnl_base_pa;

// only working if using identity mapping
uint64_t va2phy(uint64_t cr3, uint64_t virtual_address) {
    const uint64_t pml4_offset_mask = 0x1FF;
    const uint64_t pdpte_offset_mask = 0x1FF;
    const uint64_t pde_offset_mask = 0x1FF;
    const uint64_t pte_offset_mask = 0x1FF;
    const uint64_t pfn_offset_mask = 0xFFF;
    const uint64_t pfn_mask = 0xFFFFFFFFF000;
    uint64_t pml4_offset = (virtual_address >> 39) & pml4_offset_mask;
    uint64_t pdpte_offset = (virtual_address >> 30) & pdpte_offset_mask;
    uint64_t pde_offset = (virtual_address >> 21) & pde_offset_mask;
    uint64_t pte_offset = (virtual_address >> 12) & pte_offset_mask;
    uint64_t page_offset = virtual_address & pfn_offset_mask;
    uint64_t pml4_base = cr3 & pfn_mask;
    uint64_t pml4_entry_addr = pml4_base + (pml4_offset * 8);
    uint64_t pdpt_base = (*(uint64_t*)pml4_entry_addr) & pfn_mask;
    uint64_t pdpt_entry_addr = pdpt_base + (pdpte_offset * 8);
    uint64_t pd_base = (*(uint64_t*)pdpt_entry_addr) & pfn_mask;
    uint64_t pd_entry_addr = pd_base + (pde_offset * 8);
    uint64_t pt_base = (*(uint64_t*)pd_entry_addr) & pfn_mask;
    uint64_t pt_entry_addr = pt_base + (pte_offset * 8);
    uint64_t page_base = (*(uint64_t*)pt_entry_addr) & pfn_mask;
    uint64_t physical_address = page_base + page_offset;
    return physical_address;
}


int wcsicmp_kernel(const WCHAR* s1, const WCHAR* s2)
{
    while (*s1 && *s2)
    {
        WCHAR c1 = (*s1 >= L'A' && *s1 <= L'Z') ? *s1 + 32 : *s1;
        WCHAR c2 = (*s2 >= L'A' && *s2 <= L'Z') ? *s2 + 32 : *s2;

        if (c1 != c2)
            return (int)(c1 - c2);

        s1++;
        s2++;
    }

    return (int)(*s1 - *s2);
}


uint64_t get_module(uint64_t list_entry, const wchar_t* module)
{
    uint64_t current_entry = *(uint64_t*)list_entry;

    while (current_entry != list_entry)
    {
        uint64_t module_name_addr = *(uint64_t*)((uint8_t*)current_entry + 0x58 /* ->BaseDllName */ + 0x8 /* ->Buffer */);

        if (module_name_addr)
        {
            if (wcsicmp_kernel((wchar_t*)module_name_addr, module) == 0)
            {
                return current_entry;
            }
        }

        current_entry = *(uint64_t*)current_entry;
    }

    return 0;
}

uint64_t get_module_base(uint64_t list_entry, const wchar_t* module)
{
    uint64_t current_entry = get_module(list_entry, module);

    if (!current_entry)
    {
        return 0;
    }

    uint64_t module_base = *(uint64_t*)(uint8_t*)(current_entry + 0x30 /* ->DllBase */);

    return module_base;
}


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

STATIC

void remove_hook(void* target, UINT8 backup[12]) {
    DisableWriteProtect();
    UINT8* dst = (UINT8*)target;
    for (int i = 0; i < 12; i++) {
        dst[i] = backup[i];
    }
    RestoreWriteProtect();
}

STATIC

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


STATIC  uint8_t hex_to_byte(const char* s)
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

STATIC
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
uint64_t
HookedOslFwpKernelSetupPhase1(void* _LOADER_PARAMETER_BLOCK) {

    uint8_t* lpb_bytes = (uint8_t*)_LOADER_PARAMETER_BLOCK;
    g_ntoskrnl_base_va = get_module_base((uint64_t)(lpb_bytes + 0x10), L"ntoskrnl.exe");
    g_ntoskrnl_base_pa = va2phy(AsmReadCr3(), g_ntoskrnl_base_va);
    remove_hook(g_OslFwpKernelSetupPhase1_addr, g_backup_OslFwpKernelSetupPhase1);
    OslFwpKernelSetupPhase1_t OslFwpKernelSetupPhase1 = (OslFwpKernelSetupPhase1_t)g_OslFwpKernelSetupPhase1_addr;
    return OslFwpKernelSetupPhase1(_LOADER_PARAMETER_BLOCK);
}

STATIC
VOID __fastcall Hooked_hv_launch(
    int64_t hyperv_cr3,
    int64_t hyperv_entry_point,
    int64_t entry_point_gadget,
    uint64_t guest_kernel_cr3
)
{
    hv_launch_t hv_launch = (hv_launch_t)g_hv_launch_addr;

    remove_hook(g_hv_launch_addr, g_backup_hv_launch);

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
    int32_t  Unknown1,
    CHAR16* ModulePath,
    CHAR16* ModuleName,
    void* Unknown4,
    int64_t  Unknown5,
    int32_t  Unknown6,
    int32_t  Unknown7,
    LIST_ENTRY* LoadedModuleList,
    PPKLDR_DATA_TABLE_ENTRY  LoadedModuleEntry,
    int64_t                  Unknown10,
    int32_t  Unknown11,
    int32_t  Unknown12,
    int32_t  Unknown13,
    int32_t  Unknown14,
    int32_t  Unknown15,
    int64_t  Unknown16,
    int64_t  Unknown17
)
{

    remove_hook(g_BlLdrLoadImage_addr, g_backup_BlLdrLoadImage);
    BlLdrLoadImage_t BlLdrLoadImage = (BlLdrLoadImage_t)g_BlLdrLoadImage_addr;
    EFI_STATUS Status =
        BlLdrLoadImage(
            Unknown1,
            ModulePath,
            ModuleName,
            Unknown4,
            Unknown5,
            Unknown6,
            Unknown7,
            LoadedModuleList,
            LoadedModuleEntry,
            Unknown10,
            Unknown11,
            Unknown12,
            Unknown13,
            Unknown14,
            Unknown15,
            Unknown16,
            Unknown17
        );

    if (LoadedModuleEntry)
    {
        PKLDR_DATA_TABLE_ENTRY TableEntry =
            *(PKLDR_DATA_TABLE_ENTRY*)LoadedModuleEntry;

        if (TableEntry &&
            TableEntry->BaseDllName.Buffer &&
            !StrCmp(TableEntry->BaseDllName.Buffer, L"hvloader.dll"))
        {
            uintptr_t start = (uintptr_t)TableEntry->DllBase;
            uintptr_t end = start + TableEntry->SizeOfImage;
            g_hv_launch_addr = signature_scan(
                start,
                end,
                g_hv_launch_signature
            );

            if (g_hv_launch_addr) {
                hook_jmp64_indirect((void*)g_hv_launch_addr, (void*)Hooked_hv_launch, g_backup_hv_launch);
            }
        }
    }
    hook_jmp64_indirect((void*)g_BlLdrLoadImage_addr, (void*)HookedBlLdrLoadImage, g_backup_BlLdrLoadImage);
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
    g_BlLdrLoadImage_addr = signature_scan(start, end, g_BlLdrLoadImage_signature);

    if (g_BlLdrLoadImage_addr) {
        hook_jmp64_indirect((void*)g_BlLdrLoadImage_addr, (void*)HookedBlLdrLoadImage, g_backup_BlLdrLoadImage);
    }


    g_OslFwpKernelSetupPhase1_addr = signature_scan(start, end, g_OslFwpKernelSetupPhase1_signature);

    if (g_OslFwpKernelSetupPhase1_addr) {

        hook_jmp64_indirect((void*)g_OslFwpKernelSetupPhase1_addr, (void*)HookedOslFwpKernelSetupPhase1, g_backup_OslFwpKernelSetupPhase1);

    }

    remove_hook(g_ImgArchStartBootApplication_addr, g_backup_ImgArchStartBootApplication);
    ImgArchStartBootApplication_t ImgArchStartBootApplication = (ImgArchStartBootApplication_t)g_ImgArchStartBootApplication_addr;
    EFI_STATUS Status = ImgArchStartBootApplication(AppEntry, ImageBase, ImageSize, BootOption, ReturnArgs);
    return Status;
}



STATIC
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

    Status = g_OriginalLoadImage(
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
            g_ImgArchStartBootApplication_addr = signature_scan(start, end, g_ImgArchStartBootApplication_signature);
            if (g_ImgArchStartBootApplication_addr) {
                hook_jmp64_indirect((void*)g_ImgArchStartBootApplication_addr, (void*)HookedImgArchStartBootApplication, g_backup_ImgArchStartBootApplication);
            }
        }
        gBS->FreePool(Path);
    }

    return Status;
}


STATIC
EFI_STATUS
EFIAPI
HookedExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey) {

    gBS->ExitBootServices = g_OriginalExitBootServices;

    Print(L"\r\n\r\n");
    Print(L"========================================\r\n");
    Print(L"          Windows loading...\r\n");
    Print(L"========================================\r\n");
    Print(L"\r\n");
    if (g_ImgArchStartBootApplication_addr) {
        Print(L"bootmgfw!ImgArchStartBootApplication: 0x%p\r\n", g_ImgArchStartBootApplication_addr);
        Print(L"hooking bootmgfw!ImgArchStartBootApplication --> HookedImgArchStartBootApplication: 0x%p\r\n", HookedImgArchStartBootApplication);
    }
    else {
        gST->ConOut->SetAttribute(gST->ConOut, EFI_RED);
        Print(L"bootmgfw!ImgArchStartBootApplication Signature out of dated\\n");
        return gBS->ExitBootServices(ImageHandle, MapKey);
    }

    if (g_BlLdrLoadImage_addr) {
        Print(L"winload!BlLdrLoadImage: 0x%p\r\n", g_BlLdrLoadImage_addr);
        Print(L"hooking winload!BlLdrLoadImage --> HookedBlLdrLoadImage: 0x%p\r\n", HookedBlLdrLoadImage);
    }
    else {

        gST->ConOut->SetAttribute(gST->ConOut, EFI_RED);
        Print(L"winload!BlLdrLoadImage Signature out of dated\\n");
        return gBS->ExitBootServices(ImageHandle, MapKey);

    }



    if (g_hv_launch_addr) {


        Print(L"hvloader!hv_launch: 0x%p\r\n", g_hv_launch_addr);
        Print(L"hooking hvloader!hv_launch --> Hooked_hv_launch: 0x%p\r\n", Hooked_hv_launch);

    }

    else {

        gST->ConOut->SetAttribute(gST->ConOut, EFI_RED);
        Print(L"hvloader!hv_launch Signature out of dated\\n");
        return gBS->ExitBootServices(ImageHandle, MapKey);

    }

    if (g_OslFwpKernelSetupPhase1_addr) {


        Print(L"winload!OslFwpKernelSetupPhase1: 0x%p\r\n", g_OslFwpKernelSetupPhase1_addr);
        Print(L"hooking winload!OslFwpKernelSetupPhase1 --> HookedOslFwpKernelSetupPhase1: 0x%p\r\n", HookedOslFwpKernelSetupPhase1);

    }

    else {

        gST->ConOut->SetAttribute(gST->ConOut, EFI_RED);
        Print(L"winload!OslFwpKernelSetupPhase1 Signature out of dated\\n");
        return gBS->ExitBootServices(ImageHandle, MapKey);

    }


    Print(L"ntoskrnl.exe:\r\n");
    Print(L"  VA = 0x%016lx\r\n", g_ntoskrnl_base_va);
    Print(L"  PA = 0x%016lx\r\n", g_ntoskrnl_base_pa);
    return gBS->ExitBootServices(ImageHandle, MapKey);
}


STATIC
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

    status = gBS->HandleProtocol(
        ImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID**)&LoadedImage
    );

    if (EFI_ERROR(status))
        return status;

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
        (VOID*)(UINTN)g_relocated_DxeBase,
        ImageBase,
        ImageSize
    );

    UINTN Offset = (UINT8*)Callback - (UINT8*)ImageBase;
    IMAGE_CALLBACK NewCallback =
        (IMAGE_CALLBACK)((UINT8*)(UINTN)g_relocated_DxeBase + Offset);

    status = NewCallback(ImageHandle, gST);

    return status;
}

STATIC
EFI_STATUS
EFIAPI
callback(
    IN EFI_HANDLE         ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
)
{

    g_OriginalLoadImage = gBS->LoadImage;
    gBS->LoadImage = HookedLoadImage;
    g_OriginalExitBootServices = gBS->ExitBootServices;
    gBS->ExitBootServices = HookedExitBootServices;
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


    EFI_STATUS Status = ConvertImageMemoryType(
        AllocateAnyPages,
        EfiRuntimeServicesCode,
        callback,
        ImageHandle
    );

    return Status;
}
