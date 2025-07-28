---
title: DSP Kernel Internals
date: 2025-07-17 15:06:45 +/-0530
categories: [Android,DSP-Kernel]
tags: [android,dsp-kernel,adsprpc]     # TAG names should always be lowercase
description: In depth internals on DSP Kernel (FastRPC), mainly on adsprpc driver.
comments: false
future: true
---

## UNDER CONSTRUCTION
I'm still working on this post in my free time, you may still check out the parts I've completed. Thanks!


## Architecture

The FastRPC DSP kernel system is a comprehensive Remote Procedure Call framework that enables high-performance communication between Linux kernel/userspace applications and Digital Signal Processor subsystems on Qualcomm platforms. 

The FastRPC system implements a multi-layered architecture that facilitates communication between host Linux applications and remote DSP subsystems. The system consists of three primary layers: userspace applications, kernel driver infrastructure, and transport mechanisms.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/arch.png){: width="1000" height="1000" }

FastRPC supports communication with multiple DSP subsystems, each identified by domain IDs: ADSP (Audio, ID: 0), MDSP (Modem, ID: 1), SDSP (Sensors, ID: 2), and CDSP (Compute, ID: 3). Each domain supports different process types including Root PD, Static PDs for specific functions, and dynamic User PDs . 

The system operates through a character device interface (`/dev/adsprpc-*`) that exposes FastRPC functionality via IOCTL operations. The global `fastrpc_apps` structure (`gfa`) serves as the central coordination point, managing multiple DSP channels and maintaining per-channel context tables.

## Core Data Structures

The FastRPC DSP kernel system uses a hierarchical structure to manage communication between the Linux kernel and DSP subsystems, centered around the global `fastrpc_apps` structure and context management for individual RPC calls.

### Global Apps Structure

The `fastrpc_apps` structure serves as the central coordination point for the entire FastRPC system, instantiated as the global variable `gfa` adsprpc_shared.h:721-766 . This structure contains several key components that organize the system's resources. The `channel[NUM_CHANNELS]` array manages communication channels for different DSP domains (ADSP, MDSP, SDSP, CDSP), while `drivers` and `maps` hash lists track registered drivers and memory mappings respectively adsprpc_shared.h:722-731 . Device information is stored in `dev`, `dev_fastrpc`, and `cdev` fields, and each channel maintains its own job ID counter in the `jobid[NUM_CHANNELS]` array adsprpc_shared.h:732-741 .

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/arch.png){: width="1000" height="1000" }

Each channel context (`fastrpc_channel_ctx`) contains session management through `session[NUM_SESSIONS]` and static process domains via `spd[NUM_SESSIONS]` adsprpc_shared.h:690-691 . The most critical component for RPC tracking is the `ctxtable[FASTRPC_CTX_MAX]` array, which maintains pointers to active RPC contexts, protected by the `ctxlock` spinlock adsprpc_shared.h:713-714 . Transport logging is handled through `gmsg_log` and the transport `handle` adsprpc_shared.h:715 .

At the file level, each `fastrpc_file` structure represents a client process and contains its own `maps` hash list for memory mappings, a context list (`clst`) of type `fastrpc_ctx_lst`, and session contexts (`sctx`, `secsctx`) for secure and non-secure operations adsprpc_shared.h:848-866 . Process identification is maintained through `tgid`, channel ID (`cid`), and process domain type (`pd_type`) fields adsprpc_shared.h:871-882 .

### Context Management and Lifecycle

Each RPC invocation creates a `smq_invoke_ctx` structure that tracks the complete call lifecycle from allocation to completion adsprpc_shared.h:584-631 . The context lifecycle follows a well-defined sequence: `context_alloc` creates and initializes the context, `context_build_overlap` prepares buffer mappings, `fastrpc_transport_send` transmits the request to the DSP, completion work handles the response, and finally `context_free` cleans up resources .

During context allocation, the system searches for an available slot in the channel's context table (`chan->ctxtable[FASTRPC_CTX_MAX]`) while holding the context lock (`chan->ctxlock`) adsprpc.c:1972-1994 . The allocation process reserves slots for kernel and static RPC calls by starting user contexts from `NUM_KERNEL_AND_STATIC_ONLY_CONTEXTS` to prevent user invocations from exhausting critical system resources adsprpc.c:1975-1984 .

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/ctx.png){: width="1000" height="1000" }

The context ID (`ctx->ctxid`) uses a sophisticated encoding scheme that combines multiple components into a single identifier adsprpc_shared.h:447-456 . The encoding packs the job ID (from `me->jobid[cid]`) in the upper bits, the table index in the middle bits, and the job type (sync/async) in the lower bits using bit manipulation operations adsprpc.c:1987-1990 . This encoding allows the system to quickly extract the table index during response processing using `GET_TABLE_IDX_FROM_CTXID(ctx->ctxid)` adsprpc.c:2049 .

Context cleanup in `context_free` reverses the allocation process by removing the context from the table, decrementing reference counts on mapped buffers, and freeing associated resources like performance tracking structures adsprpc.c:2030-2096 . The function also handles the context list management by removing the context from the file's pending list and updating the active context count adsprpc.c:2064-2069 .