# HyperRev-dxe
# This is not a fully working, but just an example how you access hv_launch with hooks.
By accessing hv_lauch from dxe driver, you can potentially, change the hypervisor setup, without detection from AC.

Windows seperate VMX ROOT AND VMX GUEST by EPT PAGING.
![Screenshot](image0-8.webp)












By changing it. You can have Software inside HyperV without any kernel driver ever will be able to detect it.
# TODO:
# Inject PML4 to point at our image inside the hyperV cr3
# Hook hv.exe vmexit handler or VmEntry instructions.
# add our image to ept/npt
