---
title: IDspService HAL Interface
date: 2025-08-19 15:06:45 +/-0530
categories: [Android,DSP-Kernel]
tags: [android,dsp-kernel,adsprpc]     # TAG names should always be lowercase
description: Internals and working of Qualcomm IDspService HAL Interface.
comments: false
future: true
---

In the [previous post](https://streypaws.github.io/posts/DSP-Kernel-Internals/), we explored the internals of Qualcomm’s DSP kernel implementation of FastRPC. We looked at the overall architecture, context handling, memory management, session lifecycle, and more. We also examined how the adsprpc kernel driver exposes various interfaces to enable communication with the DSP subsystem.

The next question is: **How can we actually access and use this driver from userspace?**

> All research presented here was conducted on a rooted Samsung Galaxy S24 Ultra powered by the Snapdragon 8 Gen 3 chipset, running the July 2024 security patch. Unless otherwise noted, all observations and references are made with respect to this device.
{: .prompt-info }

## Overview

Let's check what different SELinux contexts can access the `/dev/adsprpc-smd` driver.

```shell
e3q:/ # ls -lZ /dev adsprpc-smd             
crw-rw-r-- 1 system system u:object_r:vendor_qdsp_device:s0  464,   0 2023-03-05 15:39 /dev/adsprpc-smd
```

In practice, this means that to communicate with the driver we must gain access to the `vendor_qdsp_device` SELinux context. On the device under analysis, multiple domains are permitted to issue `ioctl` calls to the adsprpc driver. The primary ones include:

- appdomain
- factory_ssc
- hal_camera_default
- hal_frcmc_default
- mediacodec
- shell **(Nice!)**
- snap_hidl
- vendor_adsprpcd
- vendor_audioadsprpcd
- vendor_cdsprpcd
- vendor_dspservice
- vendor_qvrd_vndr
- vendor_thermal-engine
- vendor_vppservice

```shell
streypaws@ubuntu:~/research$ sesearch --allow precompiled_sepolicy | grep vendor_qdsp_device | grep ioctl
allow appdomain vendor_qdsp_device:chr_file { ioctl read };
allow factory_ssc vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow hal_camera_default vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow hal_frcmc_default vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow mediacodec vendor_qdsp_device:chr_file { ioctl read };
allow shell vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow snap_hidl vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow vendor_adsprpcd vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow vendor_audioadsprpcd vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow vendor_cdsprpcd vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow vendor_dspservice vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow vendor_qvrd_vndr vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow vendor_thermal-engine vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
allow vendor_vppservice vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
```

The `shell` SELinux context is notably permitted to both `read` from the driver and issue `ioctl` calls. Consequently, any program executed through an `adb shell` session can directly interact with the driver, making this attack surface relatively accessible from a forensic standpoint if `adb` access is available. 

What intrigued me further was whether an `untrusted_app` context could indirectly reach the driver through a privileged intermediary running context. After issuing this command -


```shell
streypaws@ubuntu:~/research$ sesearch --allow precompiled_sepolicy -s shell | grep ioctl | grep dsp
allow appdomain vendor_qdsp_device:chr_file { ioctl read };
allow shell vendor_qdsp_device:chr_file { getattr ioctl lock map open read watch watch_reads };
```



    appdomain = umbrella domain for apps (untrusted_app, system_app, etc.).
    Here: it only has ioctl + read on vendor_qdsp_device.
    👉 Meaning: if an FD to /dev/adsprpc-smd is handed to an app, it can read and ioctl it.
    But apps cannot open the device themselves.

    shell = the domain used when you run stuff in an adb shell.
    Here: it has open + ioctl + read + map + … on vendor_qdsp_device.
    👉 Meaning: anything you run inside adb shell can directly open /dev/adsprpc-smd and talk to it.

3. What this means practically

    From adb shell:
    You can just open("/dev/adsprpc-smd") in your program and issue ioctls, because shell domain is trusted with open.
    → That’s why this is a reachable attack surface when you have adb access.

    From an untrusted app:
    You cannot open /dev/adsprpc-smd, because open is not allowed.
    But if another process (say, a HAL or system service in a domain that can open adsprpc) passes you an FD via Binder, then because of

allow appdomain vendor_qdsp_device:chr_file { ioctl read };

you can issue ioctls/read on that FD.


Based on my analysis, such access could indeed be possible if one of the following processes were compromised (on some devices):

```shell
e3q:/ # ps -ZA | grep -E 'appdomain|factory_ssc|hal_camera_default|hal_frcmc_default|mediacodec|shell|snap_hidl|vendor_adsprpcd|vendor_audioadsprpcd|vendor_cdsprpcd|vendor_dspservice|vendor_qvrd_vndr|vendor_thermal-engine|vendor_vppservice'
u:r:vendor_audioadsprpcd:s0    media          409     1   12428132   5024 do_sys_poll         0 S audioadsprpcd
u:r:mediacodec:s0              mediacodec    1555     1   12876556  19732 binder_ioctl_write_read 0 S samsung.software.media.c2@1.0-service
u:r:vendor_dspservice:s0       system        1574     1   12561704   4520 binder_ioctl_write_read 0 S dspservice
u:r:mediacodec:s0              mediacodec    1583     1   13034996  48648 binder_ioctl_write_read 0 S media.hwcodec
u:r:hal_camera_default:s0      cameraserver  1584     1   14348028 144180 binder_ioctl_write_read 0 S vendor.samsung.hardware.camera.provider-service_64
u:r:factory_ssc:s0             system        1631     1   12518020   4004 __skb_wait_for_more_packets 0 S factory.ssc
u:r:mediacodec:s0              mediacodec    1970     1   12764196  34228 binder_ioctl_write_read 0 S media.codec
u:r:vendor_adsprpcd:s0         system        1984     1   12449756   4980 do_sys_poll         0 S adsprpcd
u:r:vendor_cdsprpcd:s0         system        1988     1   12476380   4932 do_sys_poll         0 S cdsprpcd
u:r:mediaswcodec:s0            mediacodec    1995     1   12878648  23656 binder_ioctl_write_read 0 S media.swcodec
u:r:hal_frcmc_default:s0       system        4678     1   12440800   5836 binder_ioctl_write_read 0 S vendor.samsung.hardware.frcmc-service
u:r:vendor_thermal-engine:s0   root          5103     1   14729344   7988 sigsuspend          0 S thermal-engine-v2
u:r:adbd:s0                    shell         5827     1   12693604   7880 do_epoll_wait       0 S adbd
u:r:shell:s0                   shell         7375  5827   12416628   3188 sigsuspend          0 S sh
u:r:shell:s0                   shell         7377  7375   12414664   2336 do_sys_poll         0 S su
e3q:/ # 
```

Out of these, the ones mentioned under `binder_ioctl_write_read` wait channel look promising. These processes is currently sleeping in the kernel function `binder_ioctl_write_read` — meaning it’s waiting on a binder IPC transaction. Athough we need to check which `untrusted_app` context can invoke binder ipc calls to which of these processes.









## Conclusion



## Credits

> Hey There! If you’ve come across any bugs or have ideas for improvements, feel free to reach out to me on X!
If your suggestion proves helpful and gets implemented, I’ll gladly credit you in this dedicated Credits section. Thanks for reading!
{: .prompt-info }