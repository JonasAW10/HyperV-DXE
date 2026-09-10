# HyperRev-dxe
# This is not a fully working, but just an example how you access hv_launch with hooks.
By accessing hv_lauch from dxe driver, you can potentially, change the hypervisor setup, without detection from AC.

Windows seperate VMX ROOT AND VMX GUEST by EPT PAGING.
![Screenshot](image0-8.webp)





By changing it. You can have Software inside HyperV without any kernel driver ever will be able to detect it.




# HyperV-DXE

## Features

1. Relocate dxe image into `EfiRuntimeServicesCode` Bypass  `ExitBootServices memory terminal`
2. Hook `gBS->LoadImage` our dxe driver will get notificed then windows is booting:  `e`
3. Hook `bootmgfw!ImgArchStartBootApplication`
4. Hook `winload!BlLdrLoadImage`
5. Receive `hvloader.dll` base and `hv.exe` base

   * `hv.exe` = `hvix64.exe` on Intel
   * `hv.exe` = `hvax64.exe` on AMD
6. Hook `hvloader!hv_launch`
