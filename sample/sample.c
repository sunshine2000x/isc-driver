// SPDX-License-Identifier: GPL-2.0-only
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/random.h>
#include <linux/slab.h>

#include "isc.h"
#include "sample_uapi.h"

struct sample_dev {
	u32 id;
	struct isc_handle *isc;
	struct task_struct *task;
	struct mutex lock; /* lock for sending msg */
	u32 reg_value;     /* only for test */
};

static struct sample_dev *s;

/* a kernel thread to simulate hw irq stat notification */
static int sample_task(void *data)
{
	struct sample_dev *dev = (struct sample_dev *)data;
	struct sample_msg msg;
	unsigned short r;
	u32 irq_stat = 0;

	while (!kthread_should_stop()) {
		mutex_lock(&dev->lock);
		if (dev->isc) {
			msg.id = SAMPLE_MSG_IRQ_STAT;
			msg.irq.id = 0;
			msg.irq.stat = irq_stat++;
			isc_post(dev->isc, &msg, sizeof(msg));
			get_random_bytes(&r, sizeof(r));
			r = r % 1000 + 1; /* random time interval between two irqs */
		} else {
			r = 1000;
		}
		mutex_unlock(&dev->lock);
		mdelay(r);
	}
	return 0;
}

static s32 sample_msg_handler(void *msg, u32 len, void *arg)
{
	struct sample_dev *dev = (struct sample_dev *)arg;
	struct sample_msg *m = (struct sample_msg *)msg;

	if (!dev || !m || !len)
		return -EINVAL;

	switch (m->id) {
	case SAMPLE_MSG_READ_REG:
		m->reg.value = dev->reg_value; /*only return last one for test*/
		break;
	case SAMPLE_MSG_WRITE_REG:
		dev->reg_value = m->reg.value; /*do nothing but only save it*/
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void sample_bound(struct isc_handle *isc, void *arg)
{
	struct sample_dev *dev = (struct sample_dev *)arg;

	if (isc && dev) {
		mutex_lock(&dev->lock);
		if (!dev->isc) {
			isc_get(isc);
			dev->isc = isc;
		}
		mutex_unlock(&dev->lock);
	}
}

static void sample_unbind(void *arg)
{
	struct sample_dev *dev = (struct sample_dev *)arg;

	if (dev) {
		mutex_lock(&dev->lock);
		if (dev->isc) {
			isc_put(dev->isc);
			dev->isc = NULL;
		}
		mutex_unlock(&dev->lock);
	}
}

static struct isc_notifier_ops sample_notifier_ops = {
	.bound = sample_bound,
	.unbind = sample_unbind,
	.got = sample_msg_handler,
};

static int __init sample_init_module(void)
{
	struct sample_dev *dev;
	int rc;

	if (s)
		return -EPERM;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	mutex_init(&dev->lock);

	dev->task = kthread_run(sample_task, dev, "sample");
	if (IS_ERR(dev->task)) {
		kfree(dev);
		return PTR_ERR(dev->task);
	}

	rc = isc_register(SAMPLE_UID(dev->id), &sample_notifier_ops, dev);
	if (rc < 0) {
		pr_err("failed to call isc_register (rc=%d)\n", rc);
		kfree(dev);
		return rc;
	}

	s = dev;
	return rc;
}

static void __exit sample_exit_module(void)
{
	int rc;

	kthread_stop(s->task);

	rc = isc_unregister(SAMPLE_UID(s->id));
	if (rc < 0)
		pr_err("failed to call isc_unregister (rc=%d)\n", rc);

	kfree(s);
	s = NULL;
}

module_init(sample_init_module);
module_exit(sample_exit_module);

MODULE_DESCRIPTION("ISC Sample Driver");
MODULE_AUTHOR("sunshine2000x");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("ISC-Sample");
