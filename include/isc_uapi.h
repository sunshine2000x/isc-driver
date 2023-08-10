/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UAPI_LINUX_ISC_H_
#define _UAPI_LINUX_ISC_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define ISC_IOCTL_BASE      ('X')

#define ISC_IOCTL_BIND      _IOWR(ISC_IOCTL_BASE, 0, struct isc_bind)
#define ISC_IOCTL_SEND      _IOWR(ISC_IOCTL_BASE, 1, struct isc_send)
#define ISC_IOCTL_RECV      _IOWR(ISC_IOCTL_BASE, 2, struct isc_recv)
#define ISC_IOCTL_CLOSE     _IOWR(ISC_IOCTL_BASE, 3, int)

#define ISC_MSG_FLAG_USER   (0x00000001)

enum isc_bind_dir {
	ISC_BIND_U_2_K,
	ISC_BIND_K_2_U,
};

struct isc_bind {
	__u32 uid;
	__u16 msz;
	__u16 num;
	__u16 stat;
	__u16 dir; /* enum isc_bind_dir */
	__u32 size;
	__u64 mem;
};

struct isc_send {
	__u16 seq;
	__u16 num;
};

struct isc_recv {
	__u16 seq;
	__u16 num;
};

struct isc_msg {
	__u32 flags;
	__u16 seq;
	__u16 len;
	__s32 rc;
	__u8  d[0];
};

/* ISC internal msg ids */
#define ISC_MSG_BOUND       (0x0001)
#define ISC_MSG_UNBIND      (0x0002)

struct isc_int_msg {
	__u16 id;
	__u16 len;
};

#endif /* _UAPI_LINUX_ISC_H_ */
