---
title: Bringing USB to Life in QEMU - Kernel Build, Debug, and Redirection
date: 2025-11-07 15:06:45 +/-0530
categories: [Android,Debugging]
tags: [android,kernel,debugging,usb,emulation]     # TAG names should always be lowercase
description: A Practical Guide to USB-Enabled Android Kernel Builds and Debugging using QEMU and usbredir.
comments: false
future: true
---

Understanding the Android kernel is essential for anyone working in security research, systems programming, or OS development. As the core of the platform, the kernel mediates hardware access, process scheduling, and security boundaries. Building and running the kernel under emulation gives researchers a safe, reproducible environment to inspect internals, trace execution paths, and analyze the impact of vulnerabilities without risking real devices.

Adding `USB` support in QEMU and using USB redirection (using `usbredir`) extends that environment to hardware-facing subsystems like `USB` and `HID`, enabling realistic testing of drivers and USB-dependent attack surfaces. Combined with robust debugging (kernel symbols, GDB, KGDB, and tracing), this workflow makes it possible to reproduce complex bugs, step through the code, and validate mitigations. Ultimately, it deepens understanding and improves our ability to find and fix security issues in different `USB` drivers and `HID` stacks before they reach production.

## Overview

In this post, we will progressively build up the knowledge and tools required to study the USB/HID stack in the Android kernel.     We will start by obtaining and compiling the Android Common Kernel (ACK) with HID bus support, which forms the base. Next we will build and install [QEMU](https://www.qemu.org/) with the [usbredir](https://gitlab.freedesktop.org/spice/usbredir) extension which will help us export an USB device either as TCP client or server, for use from another (virtual) machine through the usbredir protocol. Once the environment is ready, we will dive into the usbredir protocol and see how this setup will help us communicate with the HID subsystem.

## Obtain and Compile Android Common Kernel (ACK)

Firstly we need to download the Android Kernel Source and compile it. The steps steps here are similar to the [compilation steps](https://streypaws.github.io/posts/Android-Kernel-Build-Debugging/#obtain-and-compile-android-common-kernel-ack) from my earlier blog, but with an important setting. Adding the HID layer and debugging tools related config flags to enable that subsystem.

```c
CONFIG_HID=y
CONFIG_HIDRAW=y
CONFIG_HID_SUPPORT=y
CONFIG_HID_GENERIC=y
CONFIG_HID_MULTITOUCH=y
CONFIG_DEBUG_INFO_DWARF4=y
```

Once, you're done with the above modifications, you can go ahead with the `make olddefconfig` and `make -j$(nproc)` command (as mentioned in detail in my other blog) to compile the Kernel.

## Build QEMU using usbredir extension

Let's start with building `usbredir` from source. `usbredir` is a protocol for redirection USB traffic from a single USB device, to a different (virtual) machine then the one to which the USB device is attached. In our setup we forward the QEMU instance’s USB interface to the host via a TCP connection, so we can encapsulate USB/HID protocol packets inside network traffic and drive the device from the host or other networked tools. Let's first install some dependencies - 

```c
sudo apt update
sudo apt install git python3-venv python3-pip python3-setuptools python3-tomli
sudo apt install libusb-1.0-0-dev libusb-1.0-0 meson libglib2.0-dev libslirp-dev
```

Now, we'll get the source code for `usbredir`

```c
mkdir usbredir_bin
git clone https://gitlab.freedesktop.org/spice/usbredir.git/ usbredir_src
cd usbredir_src
```

We will now use `meson` to compile it into a library form which can then later be used by the QEMU source for integration.

```c
meson setup --prefix=`realpath ../usbredir_bin/` builddir 
cd builddir
meson compile
meson install
```

The built library will be installed in the `usbredir_bin` folder. We'll reference it when building QEMU with the `--enable-usb-redir` option. Let's compile QEMU from source now.

```c
mkdir qemu_bin/
wget https://download.qemu.org/qemu-10.1.2.tar.xz
tar -xf qemu-10.1.2.tar.xz
cd qemu-10.1.2

USB_PKG="$(realpath ../usbredir_bin/lib/x86_64-linux-gnu/pkgconfig)"
QEMU_PREFIX="$(realpath ../qemu_bin)"
PKG_CONFIG_PATH="${USB_PKG}:${PKG_CONFIG_PATH}" ./configure --target-list=aarch64-softmmu --enable-usb-redir --enable-slirp --prefix="${QEMU_PREFIX}"
make -j$(nproc)
make install
```

After the installation, the new `qemu-system-aarch64` binary will be installed at the `qemu_bin` directory. We'll be using this binary to emulate the kernel with the HID stack enabled.

## Testing the Setup using the usbredir protocol

Now, that the setup is done, it's time to test it using our built kernel. We can use this handy script I created to run the emulated kernel using the custom qemu binary we just built.

```bash
#!/bin/bash
export LD_LIBRARY_PATH=$(realpath /home/vagrant/usb_research/usbredir-out/lib/x86_64-linux-gnu):$LD_LIBRARY_PATH
set -euo pipefail

QEMU="/home/vagrant/usb_research/qemu-out/bin/qemu-system-aarch64"
KERNEL="/home/vagrant/android-kernel"
ROOTFS="/home/vagrant/data/buildroot-2025.05.1/output/images/rootfs.ext2"

# sanity checks
if [ ! -f "$KERNEL/arch/arm64/boot/Image" ]; then
  echo "ERROR: kernel not found: $KERNEL/arch/arm64/boot/Image" >&2
  exit 1
fi
if [ ! -f "$ROOTFS" ]; then
  echo "ERROR: rootfs not found: $ROOTFS" >&2
  exit 1
fi

# Build QEMU args one-by-one using an array
ARGS=()

# Core machine setup
ARGS+=("-cpu" "cortex-a53")
ARGS+=("-machine" "virt")
ARGS+=("-nographic")
ARGS+=("-smp" "2")
ARGS+=("-m" "2048")

# Kernel & rootfs
ARGS+=("-kernel" "$KERNEL/arch/arm64/boot/Image")
ARGS+=("-drive" "file=$ROOTFS,format=raw,if=virtio")

ARGS+=("-append" "console=ttyAMA0 root=/dev/vda")

# Networking (user mode + USB Redir)
ARGS+=("-net" "user,hostfwd=tcp::13337-:22")
ARGS+=("-net" "nic")
ARGS+=("-serial" "mon:stdio")
ARGS+=("-usb")
ARGS+=("-device" "ich9-usb-ehci1,id=usb0")
ARGS+=("-device" "usb-redir,chardev=usbchardev,debug=0")
ARGS+=("-chardev" "socket,server=on,id=usbchardev,wait=off,host=127.0.0.1,port=1337")

# Kernel command line

# Optional debug/freeze flags
for opt in "$@"; do
  case "$opt" in
    debug)
      ARGS+=("-s")   # wait for gdb connection on localhost:1234
      ;;
    freeze)
      ARGS+=("-S")   # start paused
      ;;
    *)
      echo "Warning: unknown option '$opt' (supported: debug, freeze)" >&2
      ;;
  esac
done

# Show full command for debugging
echo "Running: $QEMU ${ARGS[*]}"

# Run QEMU
exec "$QEMU" "${ARGS[@]}"
```

The script is similar to the one I used in my [earlier blog](https://streypaws.github.io/posts/Android-Kernel-Build-Debugging/#emulate-the-android-kernel-using-qemu), but with a few extra options. The `-usb` flag activates USB functionality within the virtual machine, allowing it to recognize and handle USB devices. Next, the option `-device ich9-usb-ehci1,id=usb0` defines a USB controller based on the EHCI (Enhanced Host Controller Interface) standard. This controller, identified as `usb0`, provides high-speed connectivity and is compatible with USB 2.0 devices, ensuring that the guest system can interact with USB hardware efficiently.

The `-device usb-redir,chardev=usbchardev,debug=0` parameter adds a USB redirection interface. This feature bridges communication between the host and guest systems, enabling the transfer of USB traffic in both directions. It’s particularly useful when you want to use a host USB device directly inside the VM. 

Finally, `-chardev socket,server=on,id=usbchardev,wait=off,host=127.0.0.1,port=1337` creates a communication channel that operates as a TCP socket on `localhost:1337`. This socket acts as the data transport layer for USB redirection, linking the redirection device defined earlier (usbchardev) to the host. In essence, as discussed earlier, the virtual machine is now configured to send and receive USB data through a local TCP connection — a mechanism that can be leveraged to emulate or inject virtual USB devices for testing or development purposes.

Let's now try interacting with the USB/HID stack using the `usbredir` protocol. Let's start with a handy script to connect to the TCP port (1337) which usbredir exposes through the QEMU guest to see what data we receive -

```c
#define HOST "localhost"
#define PORT "1337"

int main(void) {
    int sock = connect_socket(HOST, PORT);
    if (sock == -1) {
        fprintf(stderr, "Failed to connect to %s:%s\n", HOST, PORT);
        return 1;
    }

    unsigned char buf[REDIR_BUF_SIZE];
    ssize_t n = receive_data(sock, buf, sizeof(buf));
    if (n > 0)
        print_buffer(buf, n);

    close_socket(sock);
    return 0;
}
```

When we run this code we get - 

![Desktop View](/assets/Android/Debugging/USB_Debugging/first.png){: width="1000" height="1000" }

As we can see, once the connection is initialized, the guest begins communication by sending a **“hello”** packet, which includes details about its version and supported capabilities. In this case, the version string **“qemu usb-redir guest 10.8.2”** and a capability value of `0xff` are visible in the data stream. The bytes that appear before this version string make up the packet header, which defines how the packet should be interpreted. 

```c
struct usbredir_header_struct {
    uint32_t type;  
    uint32_t length; 
    uint32_t id;  
}
```

Within this header, the `id` field is set to `0`, the packet length is `0x44`, and the packet type is `0`, indicating that this is the initial handshake packet from the guest. This message serves as the formal greeting in the protocol and must be properly acknowledged by the connected device before any further data exchange can occur. Let's write some more code to interact with the protocol further to see where can get -

```c
int main(void) {
    int sock = connect_socket(HOST, PORT);
    if (sock < 0) {
        fprintf(stderr, "Connecting to redir socket failed\n");
        return -1;
    }

    check_resp(sock, 0);

    uint8_t payload[1024];

    size_t len = prepare_hello_pkt(payload);
    send(sock, payload, len, 0);

    len = prepare_interface_info_pkt(payload);
    printf("--> user: Sending Interface Info Pkt...\n");
    send(sock, payload, len, 0);

    len = prepare_ep_info_pkt(payload);
    printf("--> user: Sending EP INFO Pkt...\n");
    send(sock, payload, len, 0);

    len = prepare_connect_pkt(payload);
    printf("--> user: Sending Connect Pkt...\n");
    send(sock, payload, len, 0);

    check_resp(sock, 0);

    return 0;
}
```

Once the connection with the redirection socket is established, the next step is to respond appropriately with a hello packet. This packet acts as the initial handshake, confirming that communication between the guest and the device can proceed. Interestingly, after the device sends this hello packet, the guest does not reply. Instead, it expects a specific sequence of packets from the device — namely, the `Interface Info` packet, the `Endpoint Info` packet, and finally, the `Connect` packet. These must be sent in that exact order for the session to progress smoothly.

The `Interface Info` packet informs the guest about the USB interfaces the device supports, essentially communicating what kind of functionalities the device offers. Following that, the `Endpoint Info` packet defines the USB endpoints — the data channels through which control and data transfers occur. Lastly, the `Connect` packet signals that the device is now active and ready to exchange data. The guest will wait for this final packet before proceeding with any further communication.

After sending these packets to the guest we get - 

![Desktop View](/assets/Android/Debugging/USB_Debugging/second.png){: width="600" height="600" }

As we see, once these packets are transmitted, the guest responds with a reset packet (identified as `type = 3` in the packet type enumeration). This marks a shift from the usb-redir protocol layer to standard USB-level operations. The reset packet is a crucial part of the USB enumeration process — it ensures the device starts in a stable, known state before any actual USB data exchange begins. After this handshake and reset sequence, the communication channel is fully prepared for sending real USB control and data packets over the socket, just like interacting with a physical USB device.

You can find the full code on my [Github](https://github.com/Shreyas-Penkar/usbredir-scripts).

## Conclusion

Studying the Android kernel through compilation, emulation, and debugging offers a practical path to understanding the core of the operating system. By setting up a reproducible environment using QEMU, we create a safe and flexible platform for kernel experimentation — from exploring internals and developing drivers to analyzing real-world vulnerabilities. Extending this setup with USB support and redirection using usbredir brings hardware-facing subsystems into the mix, enabling realistic testing of USB drivers and attack surfaces. When combined with advanced debugging tools like GDB, KGDB, and kernel tracing, this workflow allows step-by-step analysis of complex bugs, validation of mitigations, and in-depth study of kernel behavior.

## Credits

> Hey There! If you’ve come across any bugs or have ideas for improvements, feel free to [reach out to me on X](https://x.com/streypaws)!
If your suggestion proves helpful and gets implemented, I’ll gladly credit you in this dedicated Credits section. Thanks for reading!
{: .prompt-info }