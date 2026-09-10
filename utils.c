


typedef EFI_STATUS(EFIAPI* IMAGE_CALLBACK)(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable
    );




void remove_hook(void* target, UINT8 backup[12]) {
    UINT8* dst = (UINT8*)target;
    for (int i = 0; i < 12; i++) {
        dst[i] = backup[i];
    }
}



void hook_jmp64_indirect(void* target, void* hook, uint8_t backup[12])
{
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

EFI_STATUS
EFIAPI
ConvertImageMemoryType(
    EFI_ALLOCATE_TYPE Type,
    EFI_MEMORY_TYPE MemoryType,
    IMAGE_CALLBACK Callback,
    EFI_HANDLE ImageHandle
)
{
    EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;

    gBS->HandleProtocol(
        ImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID**)&LoadedImage
    );


    UINTN DxeImageSize;
    VOID* ImageBase = LoadedImage->ImageBase;
    UINTN ImageSize = LoadedImage->ImageSize;
    DxeImageSize = ImageSize;
    UINTN Pages = EFI_SIZE_TO_PAGES(ImageSize);
    EFI_PHYSICAL_ADDRESS Relocated_DxeBase;

    gBS->AllocatePages(
        Type,
        MemoryType,
        Pages,
        &Relocated_DxeBase
    );


    gBS->CopyMem(
        (VOID*)(UINTN)Relocated_DxeBase,
        ImageBase,
        ImageSize
    );

    UINTN Offset = (UINT8*)Callback - (UINT8*)ImageBase;
    IMAGE_CALLBACK NewCallback =
        (IMAGE_CALLBACK)((UINT8*)(UINTN)Relocated_DxeBase + Offset);

    NewCallback(ImageHandle, gST);
    return EFI_SUCCESS;
}
