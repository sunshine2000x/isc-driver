/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UAPI_LINUX_SAMPLE_H_
#define _UAPI_LINUX_SAMPLE_H_

#include <linux/types.h>

#include "isc_uid_uapi.h"

#define SAMPLE_UID(n)              isc_fourcc('s', 'a', 'm', (n) + '0')

/* send */
#define SAMPLE_MSG_READ_REG        (0x001)
#define SAMPLE_MSG_WRITE_REG       (0x002)
/* recv */
#define SAMPLE_MSG_IRQ_STAT        (0x100)

struct sample_msg {
	__u32 id;
	union {
		struct {
			__u32 offset;
			__u32 value;
		} reg;
		struct {
			__u32 id;
			__u32 stat;
		} irq;
	};
};

#endif /* _UAPI_LINUX_SAMPLE_H_ */
