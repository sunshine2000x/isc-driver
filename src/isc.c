// SPDX-License-Identifier: GPL-2.0
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>

#include "isc_uapi.h"

#include "isc.h"

#define ISC_DEV_NAME        "isc"
#define ISC_MAX_NUM         (1)
#define ISC_REFCNT_INIT_VAL (1)

struct isc_imsg {
	struct list_head entry;
	struct isc_msg *msg;
	u32 sz;
};

struct isc_async_bind {
	u32 uid;
	struct isc_notifier_ops *user_ops;
	void *user_arg;
	struct isc_handle *u2k, *k2u;
	struct list_head entry;
};

struct isc_device {
	struct cdev cdev;
	dev_t devid;
	struct class *class;
	struct device *dev;
};

struct isc_mem {
	void *va;
	dma_addr_t pa;
	u32 sz;
};

struct isc_cus {
	struct list_head *rp, *wp;
};

struct isc_handle {
	struct kref ref;
	struct device *dev;
	struct file *fh;
	wait_queue_head_t wait;
	struct isc_async_bind *ib;
	refcount_t nowait, noack;
	unsigned int noack_max;
	struct isc_mem k2u_mem;
	struct isc_mem u2k_mem;
	struct isc_cus k2u_cus;
	struct isc_cus u2k_cus;
	struct list_head buf_list;
	u32 seq_num;
	bool en_k2u, en_u2k;
};

static LIST_HEAD(bind_list);
static DEFINE_MUTEX(bind_lock);
static struct isc_device *dev;

static inline bool isc_test(refcount_t *r)
{
	return refcount_read(r) == ISC_REFCNT_INIT_VAL;
}

static int isc_mem_alloc(struct device *dev, u32 sz, struct isc_mem *mem)
{
	mem->va = dma_alloc_coherent(dev, sz, &mem->pa, GFP_KERNEL);
	if (!mem->va)
		return -ENOMEM;
	mem->sz = sz;
	return 0;
}

static int isc_mem_free(struct device *dev, struct isc_mem *mem)
{
	if (mem->va)
		dma_free_coherent(dev, mem->sz, mem->va, mem->pa);
	return 0;
}

static int isc_create_msg_queue(u8 *mem, u16 msz, u16 num, struct list_head **h)
{
	struct isc_imsg *m;
	struct list_head *head;
	u32 item_sz = msz + sizeof(struct isc_msg);
	u16 i;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	INIT_LIST_HEAD(&m->entry);
	head = &m->entry;

	m->sz = msz;
	m->msg = (struct isc_msg *)mem;

	for (i = 1; i < num; i++) {
		m = kzalloc(sizeof(*m), GFP_KERNEL);
		if (!m)
			return -ENOMEM;
		list_add_tail(&m->entry, head);

		m->sz = msz;
		m->msg = (struct isc_msg *)(mem + i * item_sz);
	}
	*h = head;
	return 0;
}

static int isc_destroy_msg_queue(struct list_head *h)
{
	struct isc_imsg *m;
	struct list_head *i, *n;

	if (!h)
		return 0;

	list_for_each_safe(i, n, h) {
		list_del(i);
		m = container_of(i, struct isc_imsg, entry);
		kfree(m);
	}

	m = container_of(h, struct isc_imsg, entry);
	kfree(m);
	return 0;
}

static void isc_free(struct kref *ref)
{
	struct isc_handle *isc = container_of(ref, struct isc_handle, ref);

	isc_destroy_msg_queue(isc->k2u_cus.wp);
	isc_mem_free(isc->dev, &isc->k2u_mem);
	isc_destroy_msg_queue(isc->u2k_cus.rp);
	isc_mem_free(isc->dev, &isc->u2k_mem);
	kfree(isc);
}

static int _isc_post(struct isc_handle *isc, void *msg, size_t len, bool user)
{
	struct isc_cus *cus = &isc->k2u_cus;
	struct isc_imsg *m =
			container_of(cus->wp, struct isc_imsg, entry);

	if (!m)
		return -EINVAL;

	if (WARN_ON(refcount_read(&isc->noack) == isc->noack_max))
		return -EAGAIN;

	if (len > m->sz)
		return -EINVAL;

	m->msg->flags &= ~ISC_MSG_FLAG_USER;
	if (user)
		m->msg->flags |= ISC_MSG_FLAG_USER;

	if (msg)
		memcpy(m->msg->d, msg, len);
	m->msg->len = len;
	m->msg->seq = isc->seq_num++;
	m->msg->rc = 0;
	cus->wp = cus->wp->next;

	refcount_inc(&isc->noack);
	if (isc_test(&isc->nowait)) {
		refcount_inc(&isc->nowait);
		wake_up_interruptible(&isc->wait);
	} else {
		refcount_inc(&isc->nowait);
	}
	return 0;
}

static int isc_post_bound(struct isc_handle *isc)
{
	struct isc_int_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.id = ISC_MSG_BOUND;

	return _isc_post(isc, &msg, sizeof(msg), false);
}

static int isc_post_unbind(struct isc_handle *isc)
{
	struct isc_int_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.id = ISC_MSG_UNBIND;

	return _isc_post(isc, &msg, sizeof(msg), false);
}

int isc_register(u32 uid, struct isc_notifier_ops *ops, void *arg)
{
	struct isc_async_bind *it, *ib = NULL;

	if (!ops)
		return -EINVAL;

	mutex_lock(&bind_lock);
	list_for_each_entry(it, &bind_list, entry) {
		if (it->uid == uid) {
			ib = it;
			break;
		}
	}
	mutex_unlock(&bind_lock);

	if (!ib) {
		ib = kzalloc(sizeof(*ib), GFP_KERNEL);
		if (!ib)
			return -ENOMEM;

		ib->uid = uid;
		ib->user_ops = ops;
		ib->user_arg = arg;

		mutex_lock(&bind_lock);
		list_add_tail(&ib->entry, &bind_list);
		mutex_unlock(&bind_lock);
		return 0;
	}

	if (ib->user_ops && ib->user_ops->bound)
		return -EPERM;

	if (ib->k2u) {
		isc_post_bound(ib->k2u);
		ops->bound(ib->k2u, arg);
	}
	if (ib->u2k && ib->u2k != ib->k2u)
		isc_post_bound(ib->u2k);

	ib->user_arg = arg;
	ib->user_ops = ops;
	return 0;
}
EXPORT_SYMBOL(isc_register);

int isc_unregister(u32 uid)
{
	struct isc_async_bind *it, *ib = NULL;

	mutex_lock(&bind_lock);
	list_for_each_entry(it, &bind_list, entry) {
		if (it->uid == uid) {
			ib = it;
			break;
		}
	}
	mutex_unlock(&bind_lock);

	if (!ib)
		return -EINVAL;

	if (!ib->k2u && !ib->u2k) {
		mutex_lock(&bind_lock);
		list_del(&ib->entry);
		mutex_unlock(&bind_lock);
		kfree(ib);
		return 0;
	}

	if (ib->k2u)
		isc_post_unbind(ib->k2u);

	if (ib->user_ops->unbind)
		ib->user_ops->unbind(ib->user_arg);
	ib->user_ops = NULL;
	ib->user_arg = NULL;
	return 0;
}
EXPORT_SYMBOL(isc_unregister);

int isc_post(struct isc_handle *isc, void *msg, u32 len)
{
	return _isc_post(isc, msg, len, true);
}
EXPORT_SYMBOL(isc_post);

void isc_get(struct isc_handle *isc)
{
	kref_get(&isc->ref);
}
EXPORT_SYMBOL(isc_get);

void isc_put(struct isc_handle *isc)
{
	kref_put(&isc->ref, isc_free);
}
EXPORT_SYMBOL(isc_put);

static inline bool is_u2k(u16 dir)
{
	return dir == ISC_BIND_U_2_K;
}

static inline bool is_k2u(u16 dir)
{
	return dir == ISC_BIND_K_2_U;
}

static int isc_ioctl_bind(struct isc_handle *isc, void *arg)
{
	struct isc_bind bind;
	struct isc_async_bind *it, *ib = NULL;
	struct isc_mem *mem;
	struct isc_cus *cus;
	u32 acc_mode;
	u32 size;
	int rc;

	rc = copy_from_user(&bind, (void *)arg, sizeof(bind));
	if (rc < 0)
		return rc;

	acc_mode = isc->fh->f_flags & O_ACCMODE;
	if (acc_mode != O_RDWR)
		return -EINVAL;

	size = (bind.msz + sizeof(struct isc_msg)) * bind.num;

	if (!size)
		return -EINVAL;

	size = ALIGN(size, PAGE_SIZE);

	mutex_lock(&bind_lock);
	list_for_each_entry(it, &bind_list, entry) {
		if (it->uid != bind.uid)
			continue;

		if (is_k2u(bind.dir)) {
			if (it->k2u) {
				mutex_unlock(&bind_lock);
				return -EPERM;
			}
			it->k2u = isc;
		} else if (is_u2k(bind.dir)) {
			if (it->u2k) {
				mutex_unlock(&bind_lock);
				return -EPERM;
			}
			it->u2k = isc;
		} else {
			mutex_unlock(&bind_lock);
			return -EINVAL;
		}

		ib = it;
		break;
	}
	mutex_unlock(&bind_lock);

	if (ib) {
		if (ib->user_ops) {
			if (is_k2u(bind.dir) && ib->user_ops->bound)
				ib->user_ops->bound(isc, ib->user_arg);

			bind.stat = 1;
		}
	} else {
		ib = kzalloc(sizeof(*ib), GFP_KERNEL);
		if (!ib)
			return -ENOMEM;

		ib->uid = bind.uid;

		if (is_k2u(bind.dir))
			ib->k2u = isc;
		else if (is_u2k(bind.dir))
			ib->u2k = isc;
		else
			return -EINVAL;

		mutex_lock(&bind_lock);
		list_add_tail(&ib->entry, &bind_list);
		mutex_unlock(&bind_lock);
	}
	isc->ib = ib;

	if (is_k2u(bind.dir)) {
		mem = &isc->k2u_mem;
		cus = &isc->k2u_cus;
	} else if (is_u2k(bind.dir)) {
		mem = &isc->u2k_mem;
		cus = &isc->u2k_cus;
	} else {
		return -EINVAL;
	}

	rc = isc_mem_alloc(isc->dev, size, mem);
	if (rc < 0)
		return rc;

	rc = isc_create_msg_queue(mem->va, bind.msz, bind.num, &cus->wp);
	if (rc < 0)
		return rc;

	cus->rp = cus->wp;
	if (is_u2k(bind.dir)) {
		isc->noack_max = bind.num + ISC_REFCNT_INIT_VAL;
		isc->en_u2k = true;
	} else if (is_k2u(bind.dir)) {
		isc->en_k2u = true;
	}

	bind.mem = mem->pa;
	bind.size = size;

	return copy_to_user((void *)arg, &bind, sizeof(bind));
}

static int isc_ioctl_send(struct isc_handle *isc, void *arg)
{
	struct isc_send send;
	int rc;
	struct isc_notifier_ops *ops;
	struct isc_imsg *m;
	struct isc_cus *cus;
	u32 i;

	if (!isc->en_u2k)
		return -EPERM;

	rc = copy_from_user(&send, (void *)arg, sizeof(send));
	if (rc < 0)
		return rc;

	ops = isc->ib->user_ops;

	if (!ops || !ops->got)
		return -EPERM;

	cus = &isc->u2k_cus;
	m = container_of(cus->rp, struct isc_imsg, entry);

	if (WARN_ON(send.seq != m->msg->seq))
		return -EINVAL;

	for (i = 0; i < send.num; i++) {
		if (m->msg->flags & ISC_MSG_FLAG_USER)
			m->msg->rc = ops->got
					(m->msg->d, m->msg->len, isc->ib->user_arg);
		cus->rp = cus->rp->next;
		m = container_of(cus->rp, struct isc_imsg, entry);
	}
	return 0;
}

static int isc_ioctl_recv(struct isc_handle *isc, void *arg)
{
	struct isc_recv recv;
	struct isc_imsg *m;
	struct isc_cus *cus;
	int rc;
	u32 i;

	if (!isc->en_k2u)
		return -EINVAL;

	if (isc_test(&isc->noack))
		return -EBUSY;

	rc = copy_from_user(&recv, (void *)arg, sizeof(recv));
	if (rc < 0)
		return rc;

	cus = &isc->k2u_cus;
	m = container_of(cus->rp, struct isc_imsg, entry);

	if (WARN_ON(recv.seq != m->msg->seq))
		return -EINVAL;

	for (i = 0; i < recv.num; i++) {
		refcount_dec(&isc->noack);
		cus->rp = cus->rp->next;
	}
	return 0;
}

static void isc_unbind(struct isc_handle *isc)
{
	struct isc_async_bind *it, *ib = NULL;

	mutex_lock(&bind_lock);
	list_for_each_entry(it, &bind_list, entry) {
		if (it->uid == isc->ib->uid) {
			ib = it;
			break;
		}
	}
	mutex_unlock(&bind_lock);

	if (!ib)
		return;

	if (ib->k2u == isc) {
		ib->k2u = NULL;
		isc->en_k2u = false;
	}
	if (ib->u2k == isc) {
		ib->u2k = NULL;
		isc->en_u2k = false;
	}

	isc->ib = NULL;

	if (ib->user_ops) {
		if (ib->user_ops->unbind)
			ib->user_ops->unbind(ib->user_arg);
	} else if (!ib->k2u && !ib->u2k) {
		mutex_lock(&bind_lock);
		list_del(&ib->entry);
		mutex_unlock(&bind_lock);
		kfree(ib);
	}
}

static int isc_ioctl_close(struct isc_handle *isc, void *arg)
{
	if (isc->ib)
		isc_unbind(isc);
	return 0;
}

static long isc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long rc = -EINVAL;
	struct isc_handle *isc;

	isc = file->private_data;
	if (!isc)
		return -EINVAL;

	switch (cmd) {
	case ISC_IOCTL_BIND:
		rc = isc_ioctl_bind(isc, (void *)arg);
		break;
	case ISC_IOCTL_SEND:
		rc = isc_ioctl_send(isc, (void *)arg);
		break;
	case ISC_IOCTL_RECV:
		rc = isc_ioctl_recv(isc, (void *)arg);
		break;
	case ISC_IOCTL_CLOSE:
		rc = isc_ioctl_close(isc, (void *)arg);
		break;
	default:
		break;
	}
	return rc;
};

static unsigned int isc_poll(struct file *file, struct poll_table_struct *wait)
{
	struct isc_handle *isc = file->private_data;

	if (file->f_flags & O_NONBLOCK)
		return 0;

	if (isc_test(&isc->nowait)) {
		poll_wait(file, &isc->wait, wait);

		if (isc_test(&isc->nowait))
			return 0;
	}

	refcount_dec(&isc->nowait);
	return POLLIN | POLLRDNORM;
}

static int isc_open(struct inode *inode, struct file *file)
{
	struct isc_device *dev;
	struct isc_handle *isc;

	dev = container_of(inode->i_cdev, struct isc_device, cdev);
	isc = kzalloc(sizeof(*isc), GFP_KERNEL);
	if (!isc)
		return -ENOMEM;

	kref_init(&isc->ref);
	refcount_set(&isc->nowait, ISC_REFCNT_INIT_VAL);
	refcount_set(&isc->noack, ISC_REFCNT_INIT_VAL);
	init_waitqueue_head(&isc->wait);
	INIT_LIST_HEAD(&isc->buf_list);
	isc->dev = dev->dev;
	isc->fh = file;
	file->private_data = isc;
	return 0;
};

static int isc_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long pfn_start = vma->vm_pgoff;
	unsigned long size = vma->vm_end - vma->vm_start;

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	return remap_pfn_range(vma, vma->vm_start, pfn_start,
				   size, vma->vm_page_prot);
}

static int isc_release(struct inode *inode, struct file *file)
{
	struct isc_handle *isc = file->private_data;

	if (isc) {
		isc_ioctl_close(isc, NULL);
		isc_put(isc);
		file->private_data = NULL;
	}
	return 0;
}

static const struct file_operations isc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = isc_ioctl,
	.poll = isc_poll,
	.open = isc_open,
	.release = isc_release,
	.mmap = isc_mmap,
};

static int __init isc_init(void)
{
	int rc = 0;
	struct class *class;
	struct device *device;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	rc = alloc_chrdev_region(&dev->devid, 0, ISC_MAX_NUM, ISC_DEV_NAME);
	if (rc < 0)
		goto _alloc_err;

	class = class_create(THIS_MODULE, ISC_DEV_NAME);
	if (IS_ERR(class)) {
		rc = PTR_ERR(class);
		goto _create_err;
	}

	cdev_init(&dev->cdev, &isc_fops);
	rc = cdev_add(&dev->cdev, dev->devid, 1);
	if (rc)
		goto _add_err;

	dev->class = class;
	device = device_create(dev->class, NULL, dev->devid,
			       dev, "%s", ISC_DEV_NAME);
	if (IS_ERR(device)) {
		rc = PTR_ERR(device);
		goto _dcreate_err;
	}
	dma_set_coherent_mask(device, DMA_BIT_MASK(32));

	dev->dev = device;
	return 0;

_dcreate_err:
	unregister_chrdev_region(dev->devid, ISC_MAX_NUM);
	cdev_del(&dev->cdev);
_add_err:
	class_destroy(dev->class);
_create_err:
_alloc_err:
	kfree(dev);
	dev = NULL;
	return rc;
}

static void __exit isc_exit(void)
{
	if (!dev)
		return;

	cdev_del(&dev->cdev);
	unregister_chrdev_region(dev->devid, ISC_MAX_NUM);
	device_destroy(dev->class, dev->devid);
	class_destroy(dev->class);
	kfree(dev);
	dev = NULL;
}

module_init(isc_init);
module_exit(isc_exit);

MODULE_DESCRIPTION("ISC Generic Driver");
MODULE_AUTHOR("sunshine2000x");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ISC");
