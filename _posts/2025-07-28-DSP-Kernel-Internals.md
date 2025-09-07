---
title: Qualcomm DSP Kernel Internals
date: 2025-07-28 15:06:45 +/-0530
categories: [Android,DSP-Kernel]
tags: [android,dsp-kernel,adsprpc,driver]     # TAG names should always be lowercase
description: In depth internals on Qualcomm DSP Kernel (FastRPC implementation)
comments: false
future: true
---

When working with DSP systems and Qualcomm’s FastRPC framework, understanding the internals of the kernel-side implementation can be key to effectively navigating the codebase to understand it and to study complex bugs. In this post, we’ll take a brief look under the hood of the DSP kernel FastRPC implementation. The goal is not to cover every detail, but to build foundational context that can guide further exploration. Let’s dive in.

> The codebase referenced in this blog is the [`dsp-kernel.lnx.3.2.r4-rel`](https://git.codelinaro.org/clo/la/platform/vendor/qcom/opensource/dsp-kernel/-/tree/dsp-kernel.lnx.3.2.r4-rel?ref_type=heads) branch of the [dsp-kernel repository](https://git.codelinaro.org/clo/la/platform/vendor/qcom/opensource/dsp-kernel). I’ve also forked this branch to my GitHub for easier reference. All code snippets and references in this post are based on that version.
{: .prompt-info }

## Architecture

The FastRPC DSP kernel system is a comprehensive Remote Procedure Call framework that enables high-performance communication between Linux kernel/userspace applications and Digital Signal Processor subsystems on Qualcomm platforms . The system implements a sophisticated multi-layered architecture with three primary components: userspace applications, kernel driver infrastructure, and transport mechanisms .

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/arch1.png){: width="1000" height="1000" }

The system supports communication with four primary DSP subsystems, each identified by specific domain IDs: 

- ADSP (Audio, ID: 0) 
- MDSP (Modem, ID: 1)
- SDSP (Sensors, ID: 2)  
- CDSP (Compute, ID: 3) 

Each domain is [configured](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L344-L401) with specific subsystem names and service location parameters for proper routing and initialization.

```c
struct fastrpc_apps {
	struct fastrpc_channel_ctx *channel;
	struct cdev cdev;
	struct class *class;
	struct smq_phy_page range;
	struct hlist_head maps;
	uint32_t staticpd_flags;
	dev_t dev_no;
	int compat;
	struct hlist_head drivers;
	spinlock_t hlock;
	struct device *dev;
	/* Indicates fastrpc device node info */
	struct device *dev_fastrpc;
	unsigned int latency;
	int transport_initialized;
	/* Flag to determine fastrpc bus registration */
	int fastrpc_bus_register;
	bool legacy_remote_heap;
	/* Unique job id for each message */
	uint64_t jobid[NUM_CHANNELS];
	struct gid_list gidlist;
	struct device *secure_dev;
	struct device *non_secure_dev;
	/* Secure subsystems like ADSP/SLPI will use secure client */
	struct wakeup_source *wake_source_secure;
	/* Non-secure subsystem like CDSP will use regular client */
	struct wakeup_source *wake_source;
	uint32_t duplicate_rsp_err_cnt;
	uint32_t max_size_limit;
	struct hlist_head frpc_devices;
	struct hlist_head frpc_drivers;
	struct mutex mut_uid;
	/* Indicates nsp status */
	int fastrpc_nsp_status;
	/* Indicates secure context bank to be shared */
	int share_securecb;
	/* Indicates process type is configured for SMMU context bank */
	bool cb_pd_type;
	/* Number of lowest capacity cores for given platform */
	unsigned int lowest_capacity_core_count;
	/* Flag to check if PM QoS vote needs to be done for only one core */
	bool single_core_latency_vote;
	/* Maximum sessions allowed to be created per process */
	uint32_t max_sess_per_proc;
};
```

The system uses a hierarchical structure to manage communication between the Linux kernel and DSP subsystems, centered around the global [fastrpc_apps](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L721-L767) structure which serves as the central coordination point for the entire FastRPC system, instantiated as the global variable `gfa`. This structure contains several key components like hannel contexts, device information, and job IDs that organize the system's resources. 

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/gapps.png){: width="1000" height="1000" }

The [channel[NUM_CHANNELS]](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L722-L731) array manages communication channels for different DSP domains (ADSP, MDSP, SDSP, CDSP), while `drivers` and `maps` hash lists track registered drivers and memory mappings respectively. Device information is [stored](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L732-L742) in `dev`, `dev_fastrpc`, and `cdev` fields, and each channel maintains its own job ID counter in the `jobid[NUM_CHANNELS]` array.

Each channel context `fastrpc_channel_ctx` present in `fastrpc_apps` contains session management through [session[NUM_SESSIONS]](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L690) and static process domains via [spd[NUM_SESSIONS]](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L691). The most critical component for RPC tracking is the [ctxtable[FASTRPC_CTX_MAX]](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L713) array, which maintains pointers to active RPC contexts, protected by the `ctxlock`. Transport logging is handled through [gmsg_log](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L715) and the transport `handle`.

```c
struct fastrpc_file {
	struct hlist_node hn;
	spinlock_t hlock;
	struct hlist_head maps;
	struct hlist_head cached_bufs;
	uint32_t num_cached_buf;
	struct hlist_head remote_bufs;
	struct fastrpc_ctx_lst clst;
	struct fastrpc_session_ctx *sctx;
	struct fastrpc_buf *init_mem;
	struct kref refcount;

	/* No. of persistent headers */
	unsigned int num_pers_hdrs;
	/* Pre-allocated header buffer */
	struct fastrpc_buf *pers_hdr_buf;
	/* Pre-allocated buffer divided into N chunks */
	struct fastrpc_buf *hdr_bufs;
	/* Store snapshot of memory occupied by different buffers */
	struct memory_snapshot mem_snap;

	struct fastrpc_session_ctx *secsctx;
    
    ...
};
```

Each userspace process that opens the FastRPC device gets a [fastrpc_file](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L845-L940) structure that tracks process-specific state, memory mappings, and active RPC contexts. At the file level, each `fastrpc_file` structure represents a client process and contains [fields](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L848-L866) like, its own `maps` hash list for memory mappings, a context list (`clst`) of type `fastrpc_ctx_lst`,channel context `fastrpc_channel_ctx`, and session contexts (`sctx`, `secsctx`) for secure and non-secure operations. 

```c
struct fastrpc_ctx_lst {
	struct hlist_head pending;
	struct hlist_head interrupted;
	/* Number of active contexts queued to DSP */
	uint32_t num_active_ctxs;
	/* Queue which holds all async job contexts of process */
	struct hlist_head async_queue;
	/* Queue which holds all status notifications of process */
	struct list_head notif_queue;
};
```

The context list structure [fastrpc_ctx_lst](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L633-L642) organizes RPC contexts into pending, interrupted, and asynchronous queues, enabling efficient management of concurrent operations. Process identification is maintained through `tgid`, channel ID `cid`, and process domain type `pd_type` [fields](https://github.com/Shreyas-Penkar/dsp-kernel/blob/main/dsp/adsprpc_shared.h#L871-L882). We'll be looking at context management in depth now.

## Context Management and Lifecycle

The FastRPC context allocation system implements a sophisticated resource management mechanism that combines context table management, ID encoding, and lifecycle tracking to ensure reliable RPC communication between the kernel and DSP subsystems. 

The driver maintains per-channel context tables with [ctxtable[FASTRPC_CTX_MAX]](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L447-L456) as discussed earlier, with 1024 entries, where contexts where each channel has its own `ctxtable[FASTRPC_CTX_MAX]` array protected by a `ctxlock` spinlock for thread safety. They are allocated and tracked using a 64-bit context ID that encodes the remote PD type, job type, table index, and incrementing context ID in specific bit ranges. 

The [context allocation process](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1982-L1991) reserves entries for kernel and static calls while user handles start from a higher index, with the context ID constructed by combining job ID, table index, and job type through bit manipulation. When responses arrive, the system extracts the table index from the context ID to locate the corresponding context entry and validate the response before notifying the waiting thread. 

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/ctx1.png){: width="1000" height="1000" }

During context allocation in `context_alloc`, the system first checks if the pending context limit [MAX_PENDING_CTX_PER_SESSION(64)](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1859-L1864) has been exceeded to prevent resource exhaustion. The allocation process strategically reserves the first 70 entries [(NUM_KERNEL_AND_STATIC_ONLY_CONTEXTS)](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1982-L1984) for critical kernel and static RPC calls, while user contexts start from index 70 to ensure system operations cannot be blocked by user invocations.

The context ID encoding scheme packs multiple components into a single 64-bit identifier using [bit manipulation](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L447-L454) operations. The encoding combines the incrementing job ID `(me->jobid[cid])` in bits 16-63, the table index in bits 6-15, the job type (sync/async) in bit 4, and the process domain type in bits 0-3. This design allows efficient extraction of the table index during response processing using the [GET_TABLE_IDX_FROM_CTXID](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L122-L123) macro.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/ctx2.png){: width="1000" height="1000" }

The context lifecycle progresses through multiple states managed by different functions . After allocation, contexts are added to the file's pending list and the active [context count is incremented](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2004-L2007). The [context_save_interrupted](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2018-L2029) function moves contexts to an interrupted state when needed, transferring them from the pending list to the interrupted list. The [context_restore_interrupted](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1690-L1720) function reverses this process, moving contexts back to the pending list when they can be resumed.

Context cleanup in [context_free](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2049-L2062) systematically reverses the allocation process by first extracting the table index from the context ID and clearing the corresponding entry in the channel's context table. The function then removes the context from the file's pending list, decrements the active context count, and frees associated resources including mapped buffers and performance tracking structures. This comprehensive [cleanup](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2064-L2095) ensures proper resource management and prevents memory leaks throughout the RPC lifecycle .

## RPC Invocation Flow

The RPC invocation flow in the FastRPC DSP kernel system uses the SMQ (Shared Memory Queue) protocol and represents a complete communication pipeline between user applications and Digital Signal Processors. When a user application initiates an RPC call, it triggers a carefully orchestrated sequence that begins with the IOCTL interface and culminates in DSP execution and response handling. It is closely tied with the context management as we'll see soon.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/rpc.png){: width="1000" height="1000" }

The process starts when user applications make system calls that are intercepted by [fastrpc_device_ioctl](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7466-L7468), which serves as the primary entry point for all FastRPC operations. This function processes various IOCTL commands, with [FASTRPC_IOCTL_INVOKE](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7497-L7522) being the most common for standard RPC calls. The IOCTL handler copies user parameters into kernel space and immediately delegates to the core orchestration function.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/rpc2.png){: width="1000" height="1000" }

The central coordinator of the entire flow is [fastrpc_internal_invoke](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3383-L3441), which manages every aspect of the RPC lifecycle from context creation to cleanup. This function first validates the channel ID and session context, then determines whether to restore an interrupted context or allocate a new one. For new invocations, it calls [context_alloc](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3436-L3441) to create an `smq_invoke_ctx` structure that tracks the RPC request throughout its lifetime.


```c
struct smq_invoke_ctx {
	struct hlist_node hn;
	/* Async node to add to async job ctx list */
	struct hlist_node asyncn;
	struct completion work;
	int retval;
	int pid;
	int tgid;
	remote_arg_t *lpra;
	remote_arg64_t *rpra;
	remote_arg64_t *lrpra;		/* Local copy of rpra for put_args */
	int *fds;
	unsigned int *attrs;
	struct fastrpc_mmap **maps;
	struct fastrpc_buf *buf;
	struct fastrpc_buf *copybuf;	/*used to copy non-ion buffers */
	size_t used;
	struct fastrpc_file *fl;
	uint32_t handle;
	uint32_t sc;
	struct overlap *overs;
	struct overlap **overps;
	struct smq_msg msg;
	uint32_t *crc;
	uint64_t *perf_kernel;
	uint64_t *perf_dsp;
	unsigned int magic;
	uint64_t ctxid;
	struct fastrpc_perf *perf;
	/* response flags from remote processor */
	enum fastrpc_response_flags rsp_flags;
	/* user hint of completion time in us */
	uint32_t early_wake_time;
	/* work done status flag */
	bool is_work_done;
	/* Store Async job in the context*/
	struct fastrpc_async_job asyncjob;
	/* Async early flag to check the state of context */
	bool is_early_wakeup;
	uint32_t sc_interrupted;
	struct fastrpc_file *fl_interrupted;
	uint32_t handle_interrupted;
	uint64_t xo_time_in_us_created; /* XO Timestamp (in us) of ctx creation */
	uint64_t xo_time_in_us_interrupted; /* XO Timestamp (in us) of interrupted ctx */
	uint64_t xo_time_in_us_restored; /* XO Timestamp (in us) of restored ctx */
	int tx_index; /* index of current ctx in channel gmsg_log array */
	bool is_job_sent_to_remote_ss; /* Flag to check if job is sent to remote sub system */
};
```

The [smq_invoke_ctx](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L584-L631) structure tracks the complete lifecycle of RPC calls, containing completion synchronization, buffer management, performance metrics, and async job handling.

```c

struct smq_null_invoke {
	uint64_t ctx;			/* invoke caller context */
	uint32_t handle;	    /* handle to invoke */
	uint32_t sc;		    /* scalars structure describing the data */
};

struct smq_phy_page {
	uint64_t addr;		/* physical address */
	uint64_t size;		/* size of contiguous region */
};

struct smq_invoke_buf {
	int num;		/* number of contiguous regions */
	int pgidx;		/* index to start of contiguous region */
};

struct smq_invoke {
	struct smq_null_invoke header;
	struct smq_phy_page page;   /* remote arg and list of pages address */
};

struct smq_msg {
	uint32_t pid;           /* process group id */
	uint32_t tid;           /* thread id */
	struct smq_invoke invoke;
};

struct smq_invoke_rsp {
	uint64_t ctx;			/* invoke caller context */
	int retval;	             /* invoke return value */
};
```

The [core message types](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L318-L350) of `smq_invoke_ctx` include `smq_null_invoke` for basic invoke operations containing context, handle, and scalars, `smq_invoke` which extends the null invoke with physical page information, and `smq_msg` that wraps the invoke with process and thread identifiers. Response handling uses multiple structures: `smq_invoke_rsp` for basic responses with context and return value, `smq_invoke_rspv2` for extended responses including flags and early wake time, and `smq_notif_rspv3` for status notifications.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/rpc1.png){: width="1000" height="1000" }

Once the context is established, the system prepares for transmission by calling [get_args](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2439-L2855) to set up DMA buffers and map memory regions that will be shared between the host and DSP. The `get_args` function implements sophisticated argument marshaling that handles both ION buffers and regular memory through a multi-stage pipeline. It first maps input/output buffers by calling [fastrpc_mmap_create](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2477-L2481) for each file descriptor, creating DMA mappings and SMMU translations. 

The function then calculates metadata size requirements for headers, file descriptors, CRC, and performance counters, followed by allocating metadata buffers through [fastrpc_buf_alloc](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2602-L2603). For non-ION buffers, it copies input arguments from user space using `K_COPY_FROM_USER` and sets up the remote procedure call argument structure `(rpra)` with proper DMA mappings and page tables. This [step](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2750-L2751) is crucial because it handles the complex memory management required for cross-processor communication, including SMMU mappings and cache coherency considerations. The prepared message is then transmitted to the DSP through [fastrpc_transport_send](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3087), which abstracts the underlying transport mechanism. Let's look at the next sections in detail next which would make this process clear.

## Memory Management

The FastRPC memory management system implements a sophisticated buffer mapping architecture that coordinates memory access between user space, kernel space, and DSP virtual address spaces. This system handles multiple types of memory mappings and buffer allocations to enable efficient communication with remote DSP processors through a hierarchical allocation approach and comprehensive mapping capabilities .

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/mem4.png){: width="1000" height="1000" }

The system uses a three-tier buffer allocation strategy where [fastrpc_buf_alloc](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1574-L1576) first checks for persistent buffers through `fastrpc_get_persistent_buf`, then searches cached buffers via [fastrpc_get_cached_buf](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1511-L1571), and finally allocates new buffers using `dma_alloc_attrs` if neither option is available. The persistent buffer mechanism is optimized for metadata buffers under one page size, utilizing pre-allocated header buffers that can be reused across multiple RPC calls . The caching system maintains a list of previously allocated buffers in `fl->cached_bufs` to optimize performance by avoiding repeated allocations, with the system supporting up to 32 cached buffers with a maximum size of 8MB each, [selecting the smallest buffer](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L6341-L6346) that fits the requested size to minimize memory waste.

### Buffer Types and Allocation Strategy

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/mem.png){: width="1000" height="1000" }

The system defines four distinct buffer types in the [fastrpc_buf_type](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L462-L467) enumeration: 

- `METADATA_BUF` for small control structures
- `COPYDATA_BUF` for data copying operations 
- `INITMEM_BUF` for process initialization memory
- `USERHEAP_BUF` for user-allocated heap buffers 

Memory mapping operations are coordinated through [fastrpc_mmap_create](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L2477-L2480) which handles different mapping types including static maps, file descriptor maps, and delayed maps, supporting different flags like `FASTRPC_MAP_FD`, `FASTRPC_MAP_FD_DELAYED`, and `FASTRPC_MAP_FD_NOMAP`. Each mapping type follows a different code path within this function, with `FASTRPC_MAP_FD_NOMAP` creating mappings without full DMA setup, while other types perform complete DMA buffer attachment and mapping.

### Memory Mapping Structure and Lifecycle

```c
struct fastrpc_mmap {
	struct hlist_node hn;
	struct fastrpc_file *fl;
	struct fastrpc_apps *apps;
	int fd;
	uint32_t flags;
	struct dma_buf *buf;
	struct sg_table *table;
	struct dma_buf_attachment *attach;
	struct ion_handle *handle;
	uint64_t phys;
	size_t size;
	uintptr_t va;
	size_t len;
	int refs;
	uintptr_t raddr;
	int secure;
	bool is_persistent;			/* the map is persistenet across sessions */
	int frpc_md_index;			/* Minidump unique index */
	uintptr_t attr;
	bool in_use;				/* Indicates if persistent map is in use*/
	struct timespec64 map_start_time;
	struct timespec64 map_end_time;
	/* Mapping for fastrpc shell */
	bool is_filemap;
	bool is_dumped;				/* flag to indicate map is dumped during SSR */
	char *servloc_name;			/* Indicate which daemon mapped this */
	/* Indicates map is being used by a pending RPC call */
	unsigned int ctx_refs;
	/* Map in use for dma handle */
	unsigned int dma_handle_refs;
};
```

Each memory mapping is represented by a [fastrpc_mmap](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L768-L799) structure that tracks all relevant information including physical address `(map->phys)`, virtual address `(map->va)`, remote DSP address `(map->raddr)`, and DMA buffer details. 

The lifecycle is managed through reference counting, with [fastrpc_mmap_free](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L974-L1096) handling cleanup by unmapping DMA buffers, detaching from the DMA buffer framework, and performing security context cleanup when necessary. The [fastrpc_mmap_find](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L846-L890) function locates existing mappings by matching file descriptors, virtual addresses, and buffer objects, while [fastrpc_mmap_remove](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L921-L972) handles cleanup by searching both global and per-file mapping lists and ensuring proper reference counting before removal.

### DMA Operations and Buffer Management

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/mem2.png){: width="1000" height="1000" }

The memory management system integrates deeply with the Linux DMA buffer framework, where for each mapping, the system calls `dma_buf_attach` to attach the buffer to the appropriate SMMU device, followed by `dma_buf_map_attachment` to create the actual mapping. The physical address is extracted from the scatter-gather table, and if an SMMU context bank is configured, the address is adjusted by shifting the context bank ID into the upper 32 bits to create the final DSP-accessible address stored in `map->raddr`.
 
The system determines buffer security properties through [set_buffer_secure_type](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1186-L1227), which examines VMID permissions to classify buffers as secure or non-secure based on exclusive access patterns, and for secure buffers, performs hypervisor memory assignment using `qcom_scm_assign_mem` to grant appropriate permissions to both HLOS and DSP domains. Next, we'll explore Session and SMMU Management, as they are closely tied to memory management and DMA operations.

## Session and SMMU Management

The FastRPC DSP kernel system implements Session and SMMU (System Memory Management Unit) management that integrates secure memory mapping, context isolation, and DMA operations between user space and DSP subsystems. This architecture provides both security isolation and performance optimization through context bank sharing and coherent memory access patterns.

#### Session Management and SMMU Integration


```c
struct fastrpc_session_ctx {
	struct device *dev;
	struct fastrpc_smmu smmu;
	int used;
};

...

struct fastrpc_smmu {
	struct device *dev;
	const char *dev_name;
	int cb;
	int enabled;
	int faults;
	int secure;
	int coherent;
	int sharedcb;
	int pd_type; /* Process type on remote sub system */
	/* gen pool for QRTR */
	struct gen_pool *frpc_genpool;
	/* fastrpc gen pool buffer */
	struct fastrpc_buf *frpc_genpool_buf;
	/* fastrpc gen pool buffer fixed IOVA */
	unsigned long genpool_iova;
	/* fastrpc gen pool buffer size */
	size_t genpool_size;
};
```

The core session management revolves around the [fastrpc_session_ctx](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L664-L668) structure (a member of the `fastrpc_file` struct), which encapsulates both device information and SMMU configuration. Each session context contains an embedded [fastrpc_smmu](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L644-L662) structure that holds critical SMMU parameters including the device reference `(sess->smmu.dev)`, context bank identifier `(sess->smmu.cb)`, and various operational flags controlling memory access behavior.

The session allocation process is handled by [fastrpc_session_alloc_locked](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L5748-L5788), which searches through available sessions in a channel to find one matching the required security level, shared context bank preference, and process type. This function ensures that sessions are properly isolated based on security requirements and process types defined by `sess->smmu.pd_type`.

#### Context Bank Configuration and Security

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/smmu.png){: width="1000" height="1000" }

Context banks provide hardware-level memory isolation through the SMMU, supporting both shared and dedicated context banks [controlled by the sess->smmu.sharedcb flag](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L8136-L8187). During device tree parsing, properties like `dma-coherent` set the `sess->smmu.coherent` flag, while `qcom`,`secure-context-bank` determines the security level.

Context bank addressing is implemented through a 32-bit shift operation where the context bank ID is embedded in the upper bits of the physical address [(map->phys += ((uint64_t)sess->smmu.cb << 32))](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1441-L1448). This encoding allows the DSP subsystem to identify which context bank should handle memory accesses for proper isolation, creating domain-specific address spaces for different DSP subsystems while maintaining efficient DMA operations through the shared SMMU infrastructure.

Each FastRPC file context maintains separate session references for secure and non-secure operations through `fl->secsctx` and `fl->sctx` respectively. The secure session allocation is handled by [fastrpc_session_alloc_secure_memory](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L5951-L5975), which specifically allocates context banks for secure memory operations and integrates with TrustZone through SCM calls.

#### DMA Operations and Memory Mapping

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/smmu2.png){: width="1000" height="1000" }

The SMMU integration becomes critical during memory mapping operations, where buffers are attached to the appropriate SMMU device based on security requirements. As discussed earlier, the system performs DMA operations through a sophisticated buffer mapping process that begins with [dma_buf_attach](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1397-L1408) to associate buffers with SMMU devices, using the session's SMMU device context (either secure or non-secure depending on the buffer type).

Following attachment, as we saw earlier, [dma_buf_map_attachment](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1418-L1428) creates the actual memory mappings with bidirectional DMA access. The system applies coherency attributes based on `sess->smmu.coherent` to optimize cache operations.

#### Memory Protection and Address Encoding

Memory protection is enforced through specific DMA attributes and hypervisor calls. The system applies `DMA_ATTR_DELAYED_UNMAP` to prevent premature buffer unmapping and `DMA_ATTR_SKIP_CPU_SYNC` when [IO coherency is not supported](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1410-L1416) by the SMMU context.

For secure memory access, the system uses [qcom_scm_assign_mem](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L1460-L1480) to transfer memory ownership between virtual machines, typically from QCOM_SCM_VMID_HLOS (High Level Operating System) to specific DSP domains.

## Transport Layer Implementation

The FastRPC transport layer implements a dual-transport architecture that abstracts communication mechanisms between the Linux kernel and different DSP subsystems on Qualcomm platforms, with domain-specific routing handled through a unified interface.

This layer abstracts two distinct transport protocols: **RPMSG (Remote Processor Messaging)** and **QRTR (Qualcomm Router) sockets**, enabling RPC message delivery across processor boundaries. The transport selection depends on the target DSP domain, with specific [mappings defined for each subsystem](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L344-L401).

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/transport.png){: width="1000" height="1000" }

Each DSP domain uses a specific transport mechanism based on its subsystem requirements:

- The ADSP (Audio DSP) with domain ID 0 uses RPMSG transport through the ["lpass" subsystem](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L346-L347). 
- The MDSP (Modem DSP) with domain ID 1 operates through the ["mpss" subsystem](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L366-L367). 
- The SDSP (Sensor DSP) with domain ID 2 uses the ["dsps" subsystem](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L377-L378). 
- The CDSP (Compute DSP) with domain ID 3 operates through the ["cdsp" subsystem](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L391-L392). 

The [fastrpc_transport_send](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3087) function as discussed earlier serves as the central abstraction layer that routes messages to the appropriate transport mechanism based on the channel ID. This function is called during [RPC invocation](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7073) to send messages to the remote DSP.

#### RPMSG Transport Implementation

The RPMSG transport uses the Remote Processor Messaging framework for communication. The [fastrpc_transport_send](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L202-L219) function implementation for RPMSG validates the device and sends messages using [rpmsg_send](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L215). Response handling occurs through `fastrpc_rpmsg_callback` which processes incoming data and forwards it to [fastrpc_handle_rpc_response](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L159).

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/struct.png){: width="1000" height="1000" }

The RPMSG transport maintains session state through the [frpc_transport_session_control](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L13-L22) structure, which contains an `rpmsg_device` pointer, `mutex` for synchronization, subsystem `name`, wait queue for channel availability, and an atomic flag indicating channel status. A global array [rpmsg_session_control[NUM_CHANNELS]](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L22) manages sessions for all channels.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/dmapping.png){: width="1000" height="1000" }

Domain mapping occurs through the [get_cid_from_rpdev](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L41-L68) function, which reads device tree labels to determine the appropriate FastRPC channel ID. The function [maps the domain label to the Domain ID](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L56-L65).

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/rpmsg_lifecycle.png){: width="1000" height="1000" }

The RPMSG mechanism lifecycle begins when [fastrpc_rpmsg_probe](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L70-L105) is called during device discovery. This function sets the `rpdev` pointer, marks the channel as up by setting `is_rpmsg_ch_up` to 1, and [wakes up waiting threads](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L88-L96). During teardown, [fastrpc_rpmsg_remove](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L107-L134) clears the `rpdev` pointer and sets the channel status to down.

Message transmission occurs through [fastrpc_transport_send](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L202-L219), which validates the RPMSG device and calls [rpmsg_send](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L215) to deliver messages to the DSP. This function is called from the core FastRPC layer during [RPC invocation](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3087). Incoming messages are handled by [fastrpc_rpmsg_callback](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L144-L171), which validates the channel ID and delegates to `fastrpc_handle_rpc_response` for processing.

#### QRTR Socket Transport Implementation

The QRTR socket provides an transport mechanism using the Qualcomm Router protocol. This transport maintains session control through a different [structures](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L61-L87) that includes socket information, remote server instance IDs, and work queues for message handling. Socket-based message transmission is done to transmit RPC messages to remote domains using [kernel_sendmsg](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L423) instead of the RPMSG framework. Response processing occurs through [fastrpc_socket_callback](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L350-L371) which queues work for handling incoming messages.

This implementation provides an alternative communication mechanism to the RPMSG transport, specifically designed for secure domains and specialized remote configurations. The architecture centers around the [frpc_transport_session_control](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L69-L75) structure which encapsulates socket communication state, remote server tracking, and asynchronous message handling through workqueues.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/socketarch.png){: width="1000" height="1000" }

The socket session architecture uses a global session control array [glist_session_ctrl[NUM_CHANNELS][MAX_REMOTE_ID]](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L86) to manage multiple remote domains across different channels. adsprpc_socket.c:86 Each session contains a [fastrpc_socket](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L61-L67) structure that holds the actual socket, local and remote QRTR addresses, synchronization mutex, and receive buffer for incoming messages.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/remotedomain.png){: width="1000" height="1000" }

Remote domain configuration is handled through a static configuration table that currently supports CDSP with `SECURE_PD` domain. The system encodes remote server instances using a [bit-mapped scheme](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L33-L44) where bits 0-1 represent the channel ID and bits 8-9 represent the remote domain type (SECURE_PD=0, GUEST_OS=1).

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/qrtr.png){: width="1000" height="1000" }

The communication flow begins with socket initialization through [create_socket](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L441-L469) function which creates a kernel QRTR socket and registers callback handlers. The system then registers for remote server notifications using [register_remote_server_notifications](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L481-L511) which sends a `QRTR_TYPE_NEW_LOOKUP` control packet to discover available remote services.

Control packet handling is managed through [fastrpc_recv_ctrl_pkt](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L244-L270) function which processes QRTR control messages to track remote server availability. When a `QRTR_TYPE_NEW_SERVER` packet is received, [fastrpc_recv_new_server](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L169-L203) sets the remote server online and stores the remote address, while `QRTR_TYPE_DEL_SERVER` packets trigger [fastrpc_recv_del_server](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L203-L233) to mark the server offline and initiate driver restart procedures. 

Message transmission occurs through a similar function [fastrpc_transport_send](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L387-L430) as we saw earlier, which validates the transport device state and uses `kernel_sendmsg` to send RPC messages to the remote domain. Incoming responses are handled asynchronously through `fastrpc_socket_callback` which queues work on a dedicated workqueue, and [fastrpc_socket_callback_wq](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L280-L371) processes the actual message reception and routing.

Transport validation is then performed by [verify_transport_device](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L136-L167) which ensures the socket is created, the remote server is online, and proper mutex protection is in place before allowing message transmission. This validation mechanism ensures reliable communication by preventing attempts to send messages when the transport layer is not properly established or when remote servers are unavailable.

As we see, both transport mechanics discussed above integrate with the core FastRPC system through [common interface functions](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L419-L428) like allowing the upper layers to remain transport-agnostic. The transport initialization registers the appropriate driver based on the build configuration, with RPMSG using [register_rpmsg_driver](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_rpmsg.c#L271) and socket transport [creating and configuring sockets for enabled domains](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_socket.c#L541-L611). Next, we'll explore the driver interface, which provides a clearer view of the transport layer implementation we saw just now.

## Kernel Driver Interface

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/kerninterface.png){: width="1000" height="1000" }

The Kernel Driver Interface in the FastRPC system provides a comprehensive programming interface that allows other kernel modules to register as FastRPC drivers and interact with DSP subsystems. This interface follows the Linux device driver model, implementing a bus-type architecture where FastRPC devices and drivers are managed through registration and matching systems.

#### Interface and Device Management

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/devicedriver.png){: width="1000" height="1000" }

The interface centers around two primary structures: [fastrpc_device](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/linux/fastrpc.h#L65-L72) and [fastrpc_driver](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/linux/fastrpc.h#L86-L95). 

```c
struct fastrpc_device {
	struct hlist_node hn;
	struct device dev;
	int handle;
	struct fastrpc_file *fl;
	bool dev_close;
	unsigned int refs;
};
```

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/fastrpc_device.png){: width="1000" height="1000" }

The `fastrpc_device` structure represents a device instance in the FastRPC bus system, containing fields for device list management (`hn`), the underlying Linux device structure (`dev`), process handle identifier (`handle`), associated FastRPC file context (`fl`), device closure status (`dev_close`), and reference counting (`refs`). 

```c
struct fastrpc_driver {
	struct hlist_node hn;
	struct device_driver driver;
	struct device *device;
	int handle;
	int create;
	int (*probe)(struct fastrpc_device *dev);
	int (*callback)(struct fastrpc_device *dev,
					enum fastrpc_driver_status status);
};
```

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/fastrpc_driver.png){: width="1000" height="1000" }

The `fastrpc_driver` structure defines drivers that can handle FastRPC devices, including the underlying Linux device driver (`driver`), associated device pointer (`device`), process handle (`handle`), operation mode flag (`create`), and callback functions for device probing (`probe`) and status changes (`callback`). The system implements a complete bus infrastructure with matching, probing, and removal operations through the [fastrpc_bus_type](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L8926-L8931) structure.

#### Driver Registration and Lifecycle Management

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/driverlifecycle.png){: width="1000" height="1000" }

Kernel modules register with the FastRPC system using [fastrpc_driver_register and fastrpc_driver_unregister](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/linux/fastrpc.h#L104-L110) functions. The [driver registration process](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L9016-L9039) involves adding the driver to the global driver list and checking for matching devices. When a match is found through the [fastrpc_bus_match](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L8885-L8905) function, the driver's `probe` callback is invoked, and the device becomes active.

The system provides a convenient [module_fastrpc_driver](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/linux/fastrpc.h#L146-L156) macro that automatically generates module initialization and cleanup code, eliminating boilerplate for simple drivers. This macro creates `__init` and `__exit` functions that handle driver registration and unregistration automatically.

#### DMA Buffer Management and Driver Operations

```c
struct fastrpc_dev_map_dma {
    struct dma_buf *buf;      // Shared DMA buffer object
    uint32_t attrs;           // IOMMU mapping attributes
    size_t size;              // Buffer size in bytes
    uint64_t v_dsp_addr;      // DSP virtual address after mapping
};

...

struct fastrpc_dev_unmap_dma {
    struct dma_buf *buf;      // Shared DMA buffer object
    size_t size;              // Buffer size in bytes
};

...

struct fastrpc_dev_get_hlos_pid {
    int hlos_pid;             // HLOS PID of attached device
};
```

The interface provides sophisticated DMA buffer management through the [fastrpc_driver_invoke](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L8857-L8879) function, which supports three primary operations defined in the [fastrpc_driver_invoke_nums](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/linux/fastrpc.h#L18-L22) enumeration. These operations include `FASTRPC_DEV_MAP_DMA` for mapping DMA buffers to DSP virtual address space, `FASTRPC_DEV_UNMAP_DMA` for unmapping buffers, and `FASTRPC_DEV_GET_HLOS_PID` for retrieving host process IDs.

The DMA mapping operations use specialized structures like [fastrpc_dev_map_dma and fastrpc_dev_unmap_dma](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/linux/fastrpc.h#L31-L46) that contain DMA buffer objects, IOMMU mapping attributes, buffer sizes, and DSP virtual addresses. The actual [implementation](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L8679-L8755) handles complex operations including SMMU device mapping, DSP-side mapping, and proper error handling with reference counting.

The system creates FastRPC devices dynamically through [fastrpc_device_create](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L8938-L8979), which allocates device structures, sets up device naming based on process IDs and channel IDs, and registers devices with the Linux device model. The device naming scheme incorporates HLOS PID, unique FastRPC process ID, and channel ID to ensure uniqueness across multiple sessions.

## APIs and Interfaces

The FastRPC system exposes a comprehensive set of IOCTL commands (22 distinct) through `/dev/adsprpc-*` device files, enabling user-space applications to invoke remote procedures, manage memory mappings, and control DSP operations. The primary interface for user-space applications consists of IOCTL commands defined with the 'R' magic number. These commands are organized into functional categories: 

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/ioctls.png){: width="1000" height="1000" }

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/categories.png){: width="1000" height="1000" }

#### RPC Invocation API

The FastRPC RPC invocation API provides multiple IOCTL commands that enable user-space applications to execute remote procedure calls on DSP subsystems with varying levels of functionality.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/rpctable.png){: width="1000" height="1000" }

The core structure [fastrpc_ioctl_invoke](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/uapi/fastrpc_shared.h#L85-L90) contains three essential fields: `handle` for the remote process handle, `sc` for scalar parameters describing the argument layout, and `pra` pointing to the remote arguments array.

```c
struct fastrpc_ioctl_invoke {
    uint32_t handle;    /* remote handle */
    uint32_t sc;        /* scalars describing the data */
    remote_arg_t *pra;  /* remote arguments list */
};

struct fastrpc_ioctl_invoke_fd {
	struct fastrpc_ioctl_invoke inv;
	int *fds;		/* fd list */
};

struct fastrpc_ioctl_invoke_attrs {
	struct fastrpc_ioctl_invoke inv;
	int *fds;		/* fd list */
	unsigned int *attrs;	/* attribute list */
};
```

The API extends this basic structure through several specialized variants that build upon the core invocation. The [fastrpc_ioctl_invoke_fd](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/uapi/fastrpc_shared.h#L91-L95) structure adds file descriptor passing capabilities by including an fds array for DMA buffer sharing. The [fastrpc_ioctl_invoke_attrs](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/uapi/fastrpc_shared.h#L95-L101) variant further extends this with buffer attributes for cache control and memory management.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/rpcflow.png){: width="1000" height="1000" }

More advanced variants provide additional functionality for data integrity and performance monitoring. The [fastrpc_ioctl_invoke_crc](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/uapi/fastrpc_shared.h#L102-L108) structure includes CRC validation capabilities, while the [fastrpc_ioctl_invoke_perf](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/include/uapi/fastrpc_shared.h#L109-L117) variant adds performance tracking through `perf_kernel` and `perf_dsp` fields for latency measurement.

The kernel driver processes these invocation requests through the main IOCTL handler, which uses a fallthrough switch statement to handle the different variants efficiently. All invocation types ultimately call `fastrpc_internal_invoke` via the [fastrpc_device_ioctl](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7466-L7526) function as we saw earlier, with the appropriate message type.

#### Memory Management API

The FastRPC memory management API provides multiple mechanisms for mapping and unmapping memory between user-space and DSP address spaces through various IOCTL commands. The system supports both legacy and modern interfaces, with the modern interface using versioned structures that include reserved fields for future extensions.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/memapi.png){: width="1000" height="1000" }

The modern memory mapping interface centers around two primary structures: [fastrpc_ioctl_mem_map and fastrpc_ioctl_mem_unmap](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L230-L245). The mapping structure contains a version field set to 0 initially and uses a union to either hold the actual mapping parameters in [fastrpc_mem_map](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L47-L63) or reserved space for future extensions. The core mapping parameters include an ION file descriptor, buffer offset, mapping flags, SMMU attributes, input virtual address, buffer length, and an output field for the remote DSP virtual address.

```c
struct fastrpc_ioctl_mem_map {
    int version;        /* Initial version 0 */
    union {
        struct fastrpc_mem_map m;
        int reserved[MAP_RESERVED_NUM];
    };
};

struct fastrpc_mem_map {
    int fd;             /* ion fd */
    int offset;         /* buffer offset */
    uint32_t flags;     /* flags defined in enum fastrpc_map_flags */
    int attrs;          /* buffer attributes used for SMMU mapping */
    uintptr_t vaddrin;  /* buffer virtual address */
    size_t length;      /* buffer length */
    uint64_t vaddrout;  /* [out] remote virtual address */
};
...

struct fastrpc_ioctl_mem_unmap {
    int version;        /* Initial version 0 */
    union {
        struct fastrpc_mem_unmap um;
        int reserved[UNMAP_RESERVED_NUM];
    };
};

struct fastrpc_mem_unmap {
    int fd;             /* ion fd */
    uint64_t vaddr;     /* remote process (dsp) virtual address */
    size_t length;      /* buffer size */
};
```

The kernel implementation handles these modern memory operations through [fastrpc_internal_mem_map and fastrpc_internal_mem_unmap](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L5547-L5659) functions. The mapping process first verifies that DSP process initialization has completed, then creates an SMMU mapping using `fastrpc_mmap_create`, and finally establishes the DSP-side mapping through `fastrpc_mem_map_to_dsp`. The unmapping process reverses this by removing the DSP mapping first, then cleaning up the SMMU mapping.

The IOCTL dispatcher in [fastrpc_mmap_device_ioctl](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7340-L7464) routes the modern memory commands `FASTRPC_IOCTL_MEM_MAP` and `FASTRPC_IOCTL_MEM_UNMAP` to their respective internal handlers. This function also handles the legacy interfaces including `FASTRPC_IOCTL_MMAP`, `FASTRPC_IOCTL_MUNMAP`, their 64-bit variants, and the file descriptor-based unmapping command `FASTRPC_IOCTL_MUNMAP_FD`.

#### Initialization and Configuration API

The FastRPC initialization API provides a structured way for applications to initialize DSP processes and configure the FastRPC environment through two primary IOCTL commands and their associated data structures. 

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/initapi.png){: width="1000" height="1000" }

The basic initialization uses `FASTRPC_IOCTL_INIT` with the [fastrpc_ioctl_init](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L158-L167) structure, while enhanced initialization uses `FASTRPC_IOCTL_INIT_ATTRS` with the [fastrpc_ioctl_init_attrs](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L167-L172) structure that extends the basic structure with additional attributes and signature length fields.

```c
struct fastrpc_ioctl_init {
    uint32_t flags;     /* one of FASTRPC_INIT_* macros */
    uintptr_t file;     /* pointer to elf file */
    uint32_t filelen;   /* elf file length */
    int32_t filefd;     /* ION fd for the file */
    uintptr_t mem;      /* mem for the PD */
    uint32_t memlen;    /* mem length */
    int32_t memfd;      /* ION fd for the mem */
};

struct fastrpc_ioctl_init_attrs {
    struct fastrpc_ioctl_init init;
    int attrs;
    unsigned int siglen;
};
```

The core `fastrpc_ioctl_init` structure contains several key fields that define how the DSP process should be initialized. The flags field specifies the initialization type using [FASTRPC_INIT_*](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L4614-L4628) macros, which determines whether the process should attach to an existing process, create a new dynamic process, or create a static process. The `file` and `filelen` fields point to the ELF binary that will be loaded on the DSP, while `filefd` provides an ION file descriptor for the binary. Similarly, the `mem` and `memlen` fields specify memory allocation for the process domain (PD), with `memfd` providing the corresponding ION file descriptor for memory management.

The enhanced `fastrpc_ioctl_init_attrs` structure wraps the basic initialization structure and adds two additional fields: `attrs` for process attributes and `siglen` for signature validation length. This extended structure is processed by the same kernel function [fastrpc_init_process](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L4560-L4637), which handles both initialization variants by checking the IOCTL command type and setting appropriate default values for the additional fields when using the basic [initialization](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7559-L7575).

#### Control and Configuration API

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/controlapi.png){: width="1000" height="1000" }

The FastRPC control interface provides runtime configuration capabilities through the `FASTRPC_IOCTL_CONTROL` command, which uses the [fastrpc_ioctl_control](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L247-L256) structure to manage various system aspects. This structure contains a request type field and a union of different control structures for specific operations.

```c    
struct fastrpc_ioctl_control {
    uint32_t req;
    union {
        struct fastrpc_ctrl_latency lp;
        struct fastrpc_ctrl_kalloc kalloc;
        struct fastrpc_ctrl_wakelock wp;
        struct fastrpc_ctrl_pm pm;
        struct fastrpc_ctrl_smmu smmu;
    };
};
```

The control interface supports several key operations through different control types defined in the [enumeration](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L297-L310). Latency control (`FASTRPC_CONTROL_LATENCY`) manages power management and performance through the [fastrpc_ctrl_latency](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L64-L68) structure, which allows enabling latency control and setting target latency values in microseconds. The [implementation](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L6806-L6853) handles PM QoS requests for CPU cores to maintain system responsiveness.

Kernel allocation support is provided through `FASTRPC_CONTROL_KALLOC` using the [fastrpc_ctrl_kalloc](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L69-L71) stucture. The system automatically reports [kernel allocation support](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L6854-L6856) as available. Wakelock control (`FASTRPC_CONTROL_WAKELOCK`) manages system wake state through the [fastrpc_ctrl_wakelock](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L73-L76) structure, though this is restricted to [secure device nodes](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L6857-L6866).

Power management is handled via `FASTRPC_CONTROL_PM` using the [fastrpc_ctrl_pm](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L77-L79) structure to set timeout values for keeping the system awake. The [implementation](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L6867-L6883) enforces maximum timeout limits and requires prior wakelock enablement. SMMU configuration is managed through `FASTRPC_CONTROL_SMMU` with the [fastrpc_ctrl_smmu](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L81-L83) structure for shared context bank settings.

```c
struct fastrpc_ioctl_capability {
    uint32_t domain;
    uint32_t attribute_ID;
    uint32_t capability;
};
```

The capability query API allows applications to discover DSP capabilities using the [fastrpc_ioctl_capability](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L258-L262) structure. This structure specifies the DSP `domain`, `attribute ID`, and receives the `capability` result. The compatibility layer provides equivalent 32-bit structures for cross-architecture [support](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L242-L258), with [translation functions](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L658-L681) handling the conversion between 32-bit and 64-bit formats.

#### DSP Signal API

The DSP Signal API provides inter-process synchronization primitives between user-space and DSP processes through a set of [IOCTL operations](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L41-L46) defined in the FastRPC kernel driver. The system implements a signal-based communication mechanism where user-space processes can create, signal, wait on, and destroy synchronization objects that coordinate with DSP subsystems.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/dspmap.png){: width="1000" height="1000" }

The signal operations are implemented through [five main IOCTL commands](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7595-L7638) that handle the complete lifecycle of DSP signals. The `FASTRPC_IOCTL_DSPSIGNAL_CREATE` operation allocates a new signal with a specified ID and [initializes](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7167-L7238) its completion object in the `DSPSIGNAL_STATE_PENDING` state. The `FASTRPC_IOCTL_DSPSIGNAL_SIGNAL` operation via the [fastrpc_dspsignal_signal](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7034-L7078) function sends a signal message to the DSP using the unique FastRPC process ID, encoding both the process ID and signal ID into a 64-bit message that gets transmitted via the transport layer. 

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/dsp.png){: width="1000" height="1000" }

```c
struct fastrpc_ioctl_dspsignal_wait {
    uint32_t signal_id;     /* Signal ID */
    uint32_t timeout_usec;  /* Timeout in microseconds. UINT32_MAX for infinite wait */
};

struct fastrpc_ioctl_dspsignal_cancel_wait {
	uint32_t signal_id; /* Signal ID */
};
```

The waiting mechanism is handled by `FASTRPC_IOCTL_DSPSIGNAL_WAIT` via the [fastrpc_ioctl_dspsignal_wait](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L220-L223) struct, which supports configurable timeouts specified in microseconds, with `UINT32_MAX` representing an infinite wait. The [implementation](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7081-L7164) uses Linux completion objects to block the calling thread until the signal is received from the DSP or the timeout expires. When the DSP responds with a signal, the [handle_remote_signal](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L5790-L5839) function processes the incoming message, extracts the process ID and signal ID, and completes the corresponding completion object to wake up waiting threads.


The signal structures are organized into groups for efficient memory management, with each fastrpc_file structure containing an [array of signal group pointers](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L922-L924) that are allocated on demand. Each signal maintains state information through the [fastrpc_dspsignal](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_shared.h#L826-L837) structure, which includes a completion object and state field tracking whether the signal is unused, pending, signaled, or canceled. The `FASTRPC_IOCTL_DSPSIGNAL_DESTROY` operation cleans up signals by setting their state to unused and completing any pending waiters, while `FASTRPC_IOCTL_DSPSIGNAL_CANCEL_WAIT` via the [fastrpc_dspsignal_destroy](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L7241-L7286) function allows for early termination of wait operations.

#### Notification and Async Response API

The FastRPC notification and async response API provides two key mechanisms for handling asynchronous operations and process lifecycle events in the DSP kernel system. 

```c
struct fastrpc_ioctl_notif_rsp {
    int domain;         /* Domain of User PD */
    int session;        /* Session ID of User PD */
    uint32_t status;    /* Status of the process */
};
```

The notification API delivers status updates about DSP process lifecycle events through the [fastrpc_ioctl_notif_rsp](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L145-L149) structure, which contains the domain ID, session ID, and process status. This notification mechanism is accessed via the `FASTRPC_IOCTL_NOTIF_RSP` IOCTL command and is processed through [fastrpc_get_notif_response](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3708-L3721) in the kernel driver.

```c
struct fastrpc_ioctl_async_response {
    uint64_t jobid;         /* job id generated by user */
    int result;             /* result from DSP */
    uint64_t *perf_kernel;
    uint64_t *perf_dsp;
    uint32_t handle;
    uint32_t sc;
};
```

The async response API supports non-blocking RPC operations through the [fastrpc_ioctl_async_response](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L136-L143) structure, which tracks job completion with a user-generated job ID, DSP result code, performance data pointers, and the original handle and scalar parameters. Async operations are initiated through `FASTRPC_INVOKE2_ASYNC` requests and responses are retrieved via `FASTRPC_INVOKE2_ASYNC_RESPONSE` through the [fastrpc_internal_invoke2](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3916-L3925) function.

```c
union fastrpc_ioctl_param {
    struct fastrpc_ioctl_invoke_async inv;
    struct fastrpc_ioctl_mem_map mem_map;
    struct fastrpc_ioctl_mem_unmap mem_unmap;
    struct fastrpc_ioctl_mmap mmap;
    struct fastrpc_ioctl_mmap_64 mmap64;
    struct fastrpc_ioctl_munmap munmap;
    struct fastrpc_ioctl_munmap_64 munmap64;
    struct fastrpc_ioctl_munmap_fd munmap_fd;
    struct fastrpc_ioctl_init_attrs init;
    struct fastrpc_ioctl_control cp;
    struct fastrpc_ioctl_capability cap;
    struct fastrpc_ioctl_invoke2 inv2;
    struct fastrpc_ioctl_dspsignal_signal sig;
    struct fastrpc_ioctl_dspsignal_wait wait;
    struct fastrpc_ioctl_dspsignal_create cre;
    struct fastrpc_ioctl_dspsignal_destroy des;
    struct fastrpc_ioctl_dspsignal_cancel_wait canc;
};
```

Both APIs are restricted to the CDSP domain and require specific DSP capabilities to be enabled, as verified during the [fastrpc_internal_invoke2 function processing](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc.c#L3874-L3888). The complete UAPI parameter union [fastrpc_ioctl_param](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/include/uapi/fastrpc_shared.h#L264-L282) provides type-safe access to all IOCTL parameters including these async and notification structures, ensuring proper memory layout for kernel-userspace communication.

## Compatibility Layer

Here we describe the FastRPC 32-bit compatibility layer that enables 32-bit userspace applications to interact with the 64-bit FastRPC kernel driver. The compatibility layer handles data structure translation and IOCTL command mapping between different word sizes.

This compatibility layer addresses the fundamental challenge that pointer sizes, integer sizes, and structure padding differ between 32-bit and 64-bit architectures, which would otherwise prevent 32-bit applications from successfully communicating with the 64-bit kernel driver.

The layer is conditionally compiled based on `CONFIG_COMPAT` and provides translation services for all FastRPC IOCTL commands including RPC invocation, memory mapping, initialization, and control operations. The related code is present in [dsp/adsprpc_compat.c](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/dsp/adsprpc_compat.c) and [dsp/adsprpc_compat.h](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a/dsp/adsprpc_compat.h).

The compatibility layer operates as an intermediary translation service between 32-bit userspace applications and the native 64-bit FastRPC driver. It intercepts IOCTL calls from 32-bit processes and performs necessary data structure conversions before forwarding them to the main driver implementation.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/comp.png){: width="1000" height="1000" }

The compatibility layer defines parallel IOCTL command constants that correspond to the native FastRPC commands but use `compat_` prefixed data structures. These commands use the same IOCTL numbers but different structure definitions. This specialized `compat_` data types ensure proper size and alignment handling.

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/compattable.png){: width="1000" height="1000" }

The data types and the conversion flow is shown below - 

- `compat_uptr_t` - 32-bit pointer representation
- `compat_uint_t` - 32-bit unsigned integer
- `compat_size_t` - 32-bit size type
- `compat_u64` - 64-bit value in 32-bit context

![Desktop View](/assets/Android/DSP-Kernel/DSP_Kernel_Internals/compatg.png){: width="1000" height="1000" }

The FastRPC compatibility layer provides seamless 32-bit to 64-bit structure translation for userspace applications. The main dispatcher [`compat_fastrpc_device_ioctl`](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L986-L1112) routes IOCTL commands to specialized conversion handlers that translate data structures between architectures.

The [`compat_fastrpc_device_ioctl`](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L986-L1112) function serves as the central entry point, examining incoming IOCTL commands and routing them to appropriate handlers:

```c
switch (cmd) {
case COMPAT_FASTRPC_IOCTL_INVOKE:
case COMPAT_FASTRPC_IOCTL_INVOKE_FD:
case COMPAT_FASTRPC_IOCTL_INVOKE_ATTRS:
    return compat_fastrpc_ioctl_invoke(filp, cmd, arg);
```

The [`compat_get_fastrpc_ioctl_invoke`](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L260-L321) function handles complex RPC invocation structure translation, including remote argument arrays and file descriptor lists. The function carefully converts pointer arrays by iterating through each `remote_arg` and translating both buffer pointers and length fields:

```c
static int compat_get_fastrpc_ioctl_invoke(
			struct compat_fastrpc_ioctl_invoke_async __user *inv32,
			struct fastrpc_ioctl_invoke_async *inv,
			unsigned int cmd, unsigned int sc)
{
	compat_uint_t u = 0;
	compat_size_t s;
	compat_uptr_t p, k;
	union compat_remote_arg *pra32;
	union remote_arg *pra;
	int err = 0, len = 0, j = 0;

	len = REMOTE_SCALARS_LENGTH(sc);

    pra = (union remote_arg *)(inv + 1);
	memcpy(&inv->inv.pra, &pra, sizeof(pra));
	memcpy(&inv->inv.sc, &sc, sizeof(sc));
	err |= get_user(u, &inv32->inv.handle);
	memcpy(&inv->inv.handle, &u, sizeof(u));
	err |= get_user(p, &inv32->inv.pra);
	if (err)
		return err;
	pra32 = compat_ptr(p);
	for (j = 0; j < len; j++) {
		err |= get_user(p, &pra32[j].buf.pv);
		memcpy((uintptr_t *)&pra[j].buf.pv, &p, sizeof(p));
		err |= get_user(s, &pra32[j].buf.len);
		memcpy(&pra[j].buf.len, &s, sizeof(s));
	}
    ...

}
```
The [`compat_get_fastrpc_ioctl_mmap`](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L556-L576) function converts memory mapping structures, translating 32-bit virtual addresses to 64-bit kernel addresses. The corresponding [`compat_put_fastrpc_ioctl_mmap`](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L613-L625) function handles the reverse conversion, ensuring DSP virtual addresses are properly communicated back to 32-bit applications.

The memory mapping dispatcher [`compat_fastrpc_mmap_device_ioctl`](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L804-L924) handles multiple mapping operations including `COMPAT_FASTRPC_IOCTL_MMAP`, `COMPAT_FASTRPC_IOCTL_MEM_MAP`, and `COMPAT_FASTRPC_IOCTL_MUNMAP`. The [`compat_get_fastrpc_ioctl_init`](https://github.com/Shreyas-Penkar/dsp-kernel/blob/b7efed3a4c788bbda3cfa1b9b3f4bc4035b8e3cb/dsp/adsprpc_compat.c#L683-L721) function converts process initialization structures, handling file pointers and memory descriptors. It translates initialization parameters including file descriptors, memory pointers, and attribute flags while preserving their semantic meaning across architectures.

## Conclusion

This concludes our brief walkthrough of the Qualcomm DSP kernel FastRPC implementation internals. We covered the overall architecture, context management, memory management, session and SMMU management, transport layer implementation, kernel driver, associated APIs, and the compatibility layer.

Hopefully, this overview provides helpful context as you dive deeper into the codebase and investigate any related bugs.
Thanks for reading!

## Credits

> Hey There! If you’ve come across any bugs or have ideas for improvements, feel free to reach out to me on X!
If your suggestion proves helpful and gets implemented, I’ll gladly credit you in this dedicated Credits section. Thanks for reading!
{: .prompt-info }
