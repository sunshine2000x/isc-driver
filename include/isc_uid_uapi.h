/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UAPI_LINUX_ISC_UID_H_
#define _UAPI_LINUX_ISC_UID_H_

#include <linux/types.h>

/* Four-character-code (FOURCC) */
#define isc_fourcc(a, b, c, d) \
	((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) | ((__u32)(d) << 24))

#endif /* _UAPI_LINUX_ISC_UID_H_ */
