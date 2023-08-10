/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ISC_H_
#define _ISC_H_

struct isc_handle;

struct isc_notifier_ops {
	void (*bound)(struct isc_handle *isc, void *arg);
	void (*unbind)(void *arg);
	s32  (*got)(void *msg, u32 len, void *arg);
};

int isc_register(u32 uid, struct isc_notifier_ops *ops, void *arg);

int isc_unregister(u32 uid);

int isc_post(struct isc_handle *isc, void *msg, u32 len);

void isc_get(struct isc_handle *isc);

void isc_put(struct isc_handle *isc);

#endif /* _ISC_H_ */
