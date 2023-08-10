<!--- SPDX-License-Identifier: GPL-2.0-only -->

# Overview
Sometimes, communication between a user application and a kernel driver is necessary in Linux-based projects. If the user application wants to communicate with the kernel driver, system IOCTLs are usually selected. Meanwhile, a polling-waiting mechanism is usually implemented for the communication in the opposite direction. Here, I would like to provide one implementation which may meet the communication requirement among user applications and kernel drivers in two directions. With the help of memeory sharing, I expect this kind of way can allow big messages to be exchanged, and have a relatively high efficiency of communication (especially, for the case that the kernel driver notifies the user application).

This repository is the implementation of ISC in kernel driver. For the implementation of ISC in user application, please refer to [ISC Library](https://github.com/sunshine2000x/isc-library).

# How does ISC work?

In practice, one user application and its kernel driver, which have the communication requirement, can directly call the function interfaces provided by ISC library and driver. The user application and the driver can be bound together with a unique "UID", so if the binding operation is successful, the communication link path is then constructed.

A typical user case is shown as follows:

```c
      c
    a a /    +-------------+  +-------------+  +-------------+  +-------------+
    p t |    |    User     |  |     User    |  |     User    |  |     User    |
    p i |    |Application 1|  |Application 2|  |Application 3|  |Application N|
    l o \    +-------------+  +-------------+  +-------------+  +-------------+
    i n             ^                |                ^                ^
                    |                |                |                |
                    |                |                |                |
      l             v                v                |                v
      i /    +----------------------------------------------------------------+
    I b |    |                                                                |
    S r |    |                          ISC  Library                          |
    C a |    |                                                                |
      r \    +----------------------------------------------------------------+
      y            |  ^              |                ^              |  ^
                   |  |              |                |              |  |
    Userspace      |  |              |                |              |  |
   --------------- |  | ------------ | -------------- | ------------ |  | -----
    Kernelspace    |  |              |                |              |  |
                   v  |              v                |              v  |
      d /    +----------------------------------------------------------------+
    I r |    |                                                                |
    S i |    |                          ISC  Driver                           |
    C v |    |                                                                |
      e \    +----------------------------------------------------------------+
      r              ^               |                ^               ^
                     |               |                |               |
      d              v               v                |               v
    u r /      +-----------+   +-----------+    +-----------+   +-----------+
    s i |      |    User   |   |    User   |    |    User   |   |    User   |
    e v |      |  Driver 1 |   |  Driver 2 |    |  Driver 3 |   |  Driver N |
    r e \      +-----------+   +-----------+    +-----------+   +-----------+
      r
```

It is allowed in ISC framework for users to self-define the size of message payload and the depth of message queue. Furthermore, they can be defined separately in two directions of the communication.

# Getting Started

Note: the building guide is by default for the target machine with Linux-based OS installed.

## ISC Library

To fetch the source and build:

```shell
git clone https://github.com/sunshine2000x/isc-library.git
cd isc-library
make
```

## ISC Driver

To fetch the source and build:

```shell
git clone https://github.com/sunshine2000x/isc-driver.git
cd isc-driver
make
```

# Test the Sample

If ISC source code on both sides are built OK, it's now ready to run the sample program on the target machine.

Firstly, go to the directory of ISC driver and install isc & sample kernel driver:

```shell
make install
```

It requires the root privilege to do the installation. Or, install them step by step:

```shell
sudo insmod out/src/isc.ko
sudo insmod out/sample/sample.ko
```

Meanwhile, they can be removed from the machine:

```shell
make remove
```

Or

```shell
sudo rmmod sample
sudo rmmod isc
```

Secondly, go to the directory of ISC library and run isc sample program:

```shell
make test
```

It also requires the root privilege to do the installation. Or, start it in another way:

```shell
sudo out/isc-test
```

By the way, if the current user on the target machine is just the superuser, root, then all "sudo" prefix in the commands must be removed before they are executed.
