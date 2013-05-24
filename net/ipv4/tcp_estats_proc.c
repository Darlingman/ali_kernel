/*
 *  fs/proc/tcp_estats_proc.c
 *
 * Authors:
 *   John Heffner <jheffner@psc.edu>
 *   Matt Mathis <mathis@psc.edu>
 *   Jeff Semke <semke@psc.edu>
 *
 * The Web10Gig project.  See http://www.web10gig.org
 *
 * Copyright © 2011, Pittsburgh Supercomputing Center (PSC).
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/pid_namespace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tcp_estats.h>

#include "../../fs/proc/internal.h"

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_wmem_max;

struct proc_dir_entry *proc_tcp_estats_dir;
static struct proc_dir_entry *proc_tcp_estats_header;

struct jump_label_key tcp_estats_key;
EXPORT_SYMBOL(tcp_estats_key);

/*
 * ESTATS variable reading/writing
 */

enum tcp_estats_connection_inos {
	PROC_CONN_SPEC_ASCII = 1,
	PROC_CONN_SPEC,
	PROC_CONN_READ,
	PROC_CONN_TUNE,
	PROC_CONN_HIGH_INO	/* Keep at the end */
};

struct estats_file {
	char *name;
	int len;
	int low_ino;
	mode_t mode;
};

#define F(name,ino,perm) { (name), sizeof (name) - 1, (ino), (perm) }
static struct estats_file estats_file_arr[] = {
	F("spec-ascii", PROC_CONN_SPEC_ASCII, S_IFREG | S_IRUGO),
	F("spec", PROC_CONN_SPEC, S_IFREG | S_IRUGO),
	F("read", PROC_CONN_READ, 0),
#if 0
	F("tune", PROC_CONN_TUNE, 0),
#endif
	F(NULL, 0, 0)
};

#define ESTATS_FILE_ARR_SIZE	(sizeof (estats_file_arr) / sizeof (struct estats_file))

static struct estats_file *file_spec_ascii = &estats_file_arr[0];
static struct estats_file *file_spec = &estats_file_arr[1];

/* This works only if the array is built in the correct order. */
static inline struct estats_file *estats_file_lookup(int ino)
{
	return &estats_file_arr[ino - 1];
}

/*
 * proc filesystem routines
 */

static struct inode *proc_estats_make_inode(struct super_block *sb, ino_t ino)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		goto out;

	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	inode->i_ino = ino;

	inode->i_uid = 0;
	inode->i_gid = 0;

      out:
	return inode;
}

#define BIG_PREFIX ((~((ino_t)(0))) / 2 + 1)

static inline ino_t ino_from_cid(int cid)
{
	return (((ino_t)cid) << 8) | BIG_PREFIX;
}

static inline ino_t ino_from_parts(ino_t dir_ino, __u16 low_ino)
{
	return (dir_ino & ~0xff) | low_ino;
}

static inline int cid_from_ino(ino_t ino)
{
	return (ino >> 8) & 0x7fffffff;
}

static inline int low_from_ino(ino_t ino)
{
	return ino & 0xff;
}

static int connection_file_open(struct inode *inode, struct file *file)
{
	int cid = cid_from_ino(inode->i_ino);
	struct tcp_estats *stats;

	read_lock_bh(&tcp_estats_linkage_lock);
	stats = tcp_estats_lookup(cid);
	if (stats == NULL || stats->estats_dead) {
		read_unlock_bh(&tcp_estats_linkage_lock);
		return -ENOENT;
	}
	tcp_estats_use(stats);
	read_unlock_bh(&tcp_estats_linkage_lock);

	return 0;
}

static int connection_file_release(struct inode *inode, struct file *file)
{
	int cid = cid_from_ino(inode->i_ino);
	struct tcp_estats *stats;

	read_lock_bh(&tcp_estats_linkage_lock);
	stats = tcp_estats_lookup(cid);
	if (stats == NULL) {
		read_unlock_bh(&tcp_estats_linkage_lock);
		return -ENOENT;
	}
	read_unlock_bh(&tcp_estats_linkage_lock);
	tcp_estats_unuse(stats);

	return 0;
}

/**  <base>/<connection>/<binary variable files>  **/
static ssize_t connection_file_rw(int read, struct file *file,
				  char *buf, size_t nbytes, loff_t *ppos)
{
	int low_ino = low_from_ino(file->f_dentry->d_inode->i_ino);
	int cid = cid_from_ino(file->f_dentry->d_inode->i_ino);
	struct tcp_estats *stats;
	struct estats_file *fp;
	struct tcp_estats_var *vp;
	int pos;
	int n;
	int err;
	estats_rwfunc_t rwfunc;
	char *page;

	/* We're only going to let them read one page at a time.
	 * We shouldn't ever read more than a page, anyway, though.
	 */
	if (nbytes > PAGE_SIZE)
		nbytes = PAGE_SIZE;

	if (!access_ok(read ? VERIFY_WRITE : VERIFY_READ, buf, nbytes))
		return -EFAULT;

	if ((page = (char *)__get_free_page(GFP_KERNEL)) == NULL)
		return -ENOMEM;

	if (!read) {
		if (copy_from_user(page, buf, nbytes))
			return -EFAULT;
	}

	fp = estats_file_lookup(low_ino);
	if (fp == NULL) {
		printk(KERN_INFO "Unregistered ETSTATS file.\n");
		return 0;
	}

	read_lock_bh(&tcp_estats_linkage_lock);
	stats = tcp_estats_lookup(cid);
	read_unlock_bh(&tcp_estats_linkage_lock);
	if (stats == NULL)
		return -ENOENT;

	lock_sock(stats->estats_sk);

	pos = 0;
	n = 0;
	for (vp = &tcp_estats_var_table[0]; vp->name && nbytes > n; vp++) {
		int varlen = tcp_estats_var_len(vp);

		if (pos > *ppos) {
			err = -ESPIPE;
			goto err_out;
		}
		if (pos == *ppos) {
			if (varlen > nbytes - n)
				break;

			if (read)
				rwfunc = vp->read;
			else
				rwfunc = vp->write;
			if (rwfunc == NULL) {
				err = -EACCES;
				goto err_out;
			}
			rwfunc(page + n, stats, vp);
			n += varlen;
			*ppos += varlen;
		}
		pos += varlen;
	}

	release_sock(stats->estats_sk);

	if (read) {
		if (copy_to_user(buf, page, n))
			return -EFAULT;
	}
	free_page((unsigned long)page);

	return n;

      err_out:
	release_sock(stats->estats_sk);

	return err;
}

static ssize_t connection_file_read(struct file *file,
				    char *buf, size_t nbytes, loff_t *ppos)
{
	return connection_file_rw(1, file, buf, nbytes, ppos);
}

static ssize_t connection_file_write(struct file *file,
				     const char *buf, size_t nbytes,
				     loff_t *ppos)
{
	return connection_file_rw(0, file, (char *)buf, nbytes, ppos);
}

static struct file_operations connection_file_fops = {
	.open = connection_file_open,
	.release = connection_file_release,
	.read = connection_file_read,
	.write = connection_file_write,
	.llseek = default_llseek
};

static size_t v6addr_str(char *dest, short *addr)
{
	int start = -1, end = -1;
	int i, j;
	int pos;

	/* Find longest subsequence of 0's in addr */
	for (i = 0; i < 8; i++) {
		if (addr[i] == 0) {
			for (j = i + 1; addr[j] == 0 && j < 8; j++) ;
			if (j - i > end - start) {
				end = j;
				start = i;
			}
			i = j;
		}
	}
	if (end - start == 1)
		start = -1;

	pos = 0;
	for (i = 0; i < 8; i++) {
		if (i > 0)
			pos += sprintf(dest + pos, ":");
		if (i == start) {
			pos += sprintf(dest + pos, ":");
			i += end - start - 1;
		} else {
			pos += sprintf(dest + pos, "%hx", ntohs(addr[i]));
		}
	}

	return pos;
}

/**  <base>/<connection>/spec_ascii  **/
static ssize_t connection_spec_ascii_read(struct file *file, char *buf,
					  size_t nbytes, loff_t * ppos)
{
	u32 local_addr, remote_addr;
	u16 local_port, remote_port;
	int cid;
	struct tcp_estats *stats;
	struct tcp_estats_directs *vars;
	char tmpbuf[100];
	int len = 0;

	if (*ppos != 0)
		return 0;

	cid = cid_from_ino(file->f_dentry->d_parent->d_inode->i_ino);

	read_lock_bh(&tcp_estats_linkage_lock);
	stats = tcp_estats_lookup(cid);
	read_unlock_bh(&tcp_estats_linkage_lock);
	if (stats == NULL)
		return -ENOENT;
	vars = &stats->estats_vars;

	if (vars->LocalAddressType == TCP_ESTATS_ADDRTYPE_IPV4) {
		/* These values should not change while stats are linked.
		 * We don't need to lock the sock. */
		memcpy(&local_addr, &vars->LocalAddress, 4);
		local_addr = ntohl(local_addr);
		memcpy(&remote_addr, &vars->RemAddress, 4);
		remote_addr = ntohl(remote_addr);
		local_port = vars->LocalPort;
		remote_port = vars->RemPort;

		len = sprintf(tmpbuf, "%d.%d.%d.%d:%d %d.%d.%d.%d:%d\n",
			      (local_addr >> 24) & 0xff,
			      (local_addr >> 16) & 0xff,
			      (local_addr >> 8) & 0xff,
			      local_addr & 0xff,
			      local_port,
			      (remote_addr >> 24) & 0xff,
			      (remote_addr >> 16) & 0xff,
			      (remote_addr >> 8) & 0xff,
			      remote_addr & 0xff, remote_port);
	} else if (vars->LocalAddressType == TCP_ESTATS_ADDRTYPE_IPV6) {
		local_port = vars->LocalPort;
		remote_port = vars->RemPort;

		len += v6addr_str(tmpbuf + len, (short *)&vars->LocalAddress);
		len += sprintf(tmpbuf + len, ".%d ", local_port);
		len += v6addr_str(tmpbuf + len, (short *)&vars->RemAddress);
		len += sprintf(tmpbuf + len, ".%d\n", remote_port);
	} else {
		printk(KERN_ERR
		       "connection_spec_ascii_read: LocalAddressType invalid\n");
		return 0;
	}

	len = len > nbytes ? nbytes : len;
	if (copy_to_user(buf, tmpbuf, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

static struct file_operations connection_spec_ascii_fops = {
	.open = connection_file_open,
	.release = connection_file_release,
	.read = connection_spec_ascii_read
};

/**  <base>/<connection>/  **/
static int connection_dir_readdir(struct file *filp,
				  void *dirent, filldir_t filldir)
{
	int i;
	struct inode *inode = filp->f_dentry->d_inode;
	struct estats_file *fp;

	i = filp->f_pos;
	switch (i) {
	case 0:
		if (filldir(dirent, ".", 1, i, inode->i_ino, DT_DIR) < 0)
			return 0;
		i++;
		filp->f_pos++;
		/* fall through */
	case 1:
		if (filldir
		    (dirent, "..", 2, i, proc_tcp_estats_dir->low_ino,
		     DT_DIR) < 0)
			return 0;
		i++;
		filp->f_pos++;
		/* fall through */
	default:
		i -= 2;
		if (i >= ESTATS_FILE_ARR_SIZE)
			return 1;
		for (fp = &estats_file_arr[i]; fp->name; fp++) {
			if (filldir(dirent, fp->name, fp->len, filp->f_pos,
				    ino_from_parts(inode->i_ino, fp->low_ino),
				    fp->mode >> 12) < 0)
				return 0;
			filp->f_pos++;
		}
	}

	return 1;
}

static struct dentry *connection_dir_lookup(struct inode *dir,
					    struct dentry *dentry,
					    struct nameidata *nd)
{
	struct inode *inode;
	struct estats_file *fp;
	struct tcp_estats *stats;
	uid_t uid;

	inode = NULL;
	for (fp = &estats_file_arr[0]; fp->name; fp++) {
		if (fp->len != dentry->d_name.len)
			continue;
		if (!memcmp(dentry->d_name.name, fp->name, fp->len))
			break;
	}
	if (!fp->name)
		return ERR_PTR(-ENOENT);

	read_lock_bh(&tcp_estats_linkage_lock);
	if ((stats = tcp_estats_lookup(cid_from_ino(dir->i_ino))) == NULL) {
		read_unlock_bh(&tcp_estats_linkage_lock);
		printk(KERN_ERR "connection_dir_lookup: stats == NULL\n");
		return ERR_PTR(-ENOENT);
	}
	uid = sock_i_uid(stats->estats_sk);
	read_unlock_bh(&tcp_estats_linkage_lock);

	inode =
	    proc_estats_make_inode(dir->i_sb,
				   ino_from_parts(dir->i_ino, fp->low_ino));
	if (!inode)
		return ERR_PTR(-ENOMEM);
	inode->i_mode =
	    fp->mode ? fp->mode : S_IFREG | sysctl_tcp_estats_fperms;
	inode->i_uid = uid;
	inode->i_gid = sysctl_tcp_estats_gid;

	switch (fp->low_ino) {
	case PROC_CONN_SPEC_ASCII:
		inode->i_fop = &connection_spec_ascii_fops;
		break;
	case PROC_CONN_SPEC:
	case PROC_CONN_READ:
	case PROC_CONN_TUNE:
		inode->i_fop = &connection_file_fops;
		break;
	default:
		printk(KERN_INFO "TCP ESTATS: impossible type (%d)\n",
		       fp->low_ino);
		iput(inode);
		return ERR_PTR(-EINVAL);
	}

	d_add(dentry, inode);
	return NULL;
}

static struct inode_operations connection_dir_iops = {
	.lookup = connection_dir_lookup
};

static struct file_operations connection_dir_fops = {
	.readdir = connection_dir_readdir
};

/**  <base>/header  **/
static ssize_t header_read(struct file *file, char *buf,
			   size_t nbytes, loff_t * ppos)
{
	int len = 0;
	loff_t offset;
	char *tmpbuf;
	struct estats_file *fp;
	struct tcp_estats_var *vp;
	int n, tmp, i;
	int ret = 0;

	if ((tmpbuf = (char *)__get_free_page(GFP_KERNEL)) == NULL)
		return -ENOMEM;

	/* Web100 version string for backward compatibility,
	 * doesn't really apply anymore */
	offset = sprintf(tmpbuf, "3.0 0\n");

	for (fp = &estats_file_arr[0]; fp->name; fp++) {
		int file_offset = 0;

		if (fp == file_spec_ascii)
			continue;

		offset += sprintf(tmpbuf + offset, "\n/%s\n", fp->name);

		for (i = 0, vp = &tcp_estats_var_table[0]; vp->name; vp++, i++) {
			int varlen = tcp_estats_var_len(vp);

			/* Hack alert */
			if (fp == file_spec && i > 5)
				break;

			if (offset > PAGE_SIZE - 1024) {
				len += offset;
				if (*ppos < len) {
					n = min(offset,
						min_t(loff_t, nbytes,
						      len - *ppos));
					if (copy_to_user
					    (buf,
					     tmpbuf + max_t(loff_t,
							    *ppos - len +
							    offset, 0), n))
						return -EFAULT;
					buf += n;
					if (nbytes == n) {
						*ppos += n;
						ret = n;
						goto out;
					}
				}
				offset = 0;
			}

			offset += sprintf(tmpbuf + offset, "%s %d %d %d\n",
					  vp->name, file_offset, vp->type,
					  varlen);
			file_offset += varlen;
		}
	}
	len += offset;
	if (*ppos < len) {
		n = min(offset, min_t(loff_t, nbytes, len - *ppos));
		if (copy_to_user
		    (buf, tmpbuf + max_t(loff_t, *ppos - len + offset, 0), n))
			return -EFAULT;
		if (nbytes <= len - *ppos) {
			*ppos += nbytes;
			ret = nbytes;
			goto out;
		} else {
			tmp = len - *ppos;
			*ppos = len;
			ret = tmp;
			goto out;
		}
	}

      out:
	free_page((unsigned long)tmpbuf);
	return ret;
}

static struct file_operations header_file_operations = {
	.read = header_read
};

/**  <base>/  **/
#define FIRST_CONNECTION_ENTRY	256
#define NUMBUF_LEN		11

static int get_connection_list(int pos, int *cids, int max)
{
	struct list_head *p;
	int n;

	pos -= FIRST_CONNECTION_ENTRY;
	n = 0;

	read_lock_bh(&tcp_estats_linkage_lock);

	list_for_each(p, tcp_estats_head) {
		struct tcp_estats *stats = list_entry(p, struct tcp_estats, estats_list);

		if (sysctl_tcp_estats_only_for) {
			if (stats->estats_sk->sk_state != sysctl_tcp_estats_only_for)
				continue;
		}

		if (n >= max)
			break;
		if (!stats->estats_dead) {
			if (pos <= 0)
				cids[n++] = stats->estats_cid;
			else
				pos--;
		}
	}

	read_unlock_bh(&tcp_estats_linkage_lock);

	return n;
}

static int cid_to_str(int cid, char *buf)
{
	int len, tmp, i;

	if (cid == 0) {		/* a special case */
		len = 1;
	} else {
		tmp = cid;
		for (len = 0; len < NUMBUF_LEN - 1 && tmp > 0; len++)
			tmp /= 10;
	}

	for (i = 0; i < len; i++) {
		buf[len - i - 1] = '0' + (cid % 10);
		cid /= 10;
	}
	buf[len] = '\0';

	return len;
}

static int estats_dir_readdir(struct file *filp,
			      void *dirent, filldir_t filldir)
{
	int err;
	unsigned n, i;
	int *cids;
	int len;
	ino_t ino;
	char name[NUMBUF_LEN];
	int n_conns;

	if (filp->f_pos < FIRST_CONNECTION_ENTRY) {
		if ((err = proc_readdir(filp, dirent, filldir)) < 0)
			return err;
		filp->f_pos = FIRST_CONNECTION_ENTRY;
	}
	n_conns = (tcp_estats_conn_num + 2) * 2;
	do {
		n_conns /= 2;
		cids = kmalloc(n_conns * sizeof(int), GFP_KERNEL);
	} while (cids == NULL && n_conns > 0);
	if (cids == NULL)
		return -ENOMEM;
	n = get_connection_list(filp->f_pos, cids, n_conns);

	for (i = 0; i < n; i++) {
		ino = ino_from_cid(cids[i]);
		len = cid_to_str(cids[i], name);
		if (filldir(dirent, name, len, filp->f_pos, ino, DT_DIR) < 0) {
			break;
		}
		filp->f_pos++;
	}

	kfree(cids);

	return 0;
}

static inline struct dentry *estats_dir_dent(void)
{
	struct qstr qstr;
	struct vfsmount *mnt = current->nsproxy->pid_ns->proc_mnt;

	qstr.name = "web100";
	qstr.len = 6;
	qstr.hash = full_name_hash(qstr.name, qstr.len);

	return d_lookup(mnt->mnt_sb->s_root, &qstr);
}

void estats_proc_nlink_update(nlink_t nlink)
{
	struct dentry *dent;

	dent = estats_dir_dent();
	if (dent)
		dent->d_inode->i_nlink = nlink;
	dput(dent);
}

static void update_static_branch(int old_v, int *new_v)
{
	/* *new_v must be either 1 or 0 */
	if (*new_v)
		*new_v = 1;

	if (old_v == *new_v)
		return;

	if (*new_v)
		jump_label_inc(&tcp_estats_key);
	else
		jump_label_dec(&tcp_estats_key);
}

int tcp_estats_proc_dointvec_update(ctl_table * ctl, int write,
				    void *buffer, size_t * lenp, 
				    loff_t * ppos)
{
	unsigned n, i;
	int *cids;
	int err;
	struct qstr qstr;
	struct dentry *estats_dent, *conn_dent, *dent;
	struct inode *inode;
	struct estats_file *fp;
	char name[NUMBUF_LEN];
	int old_enabled;

	old_enabled = sysctl_tcp_estats_enabled;
	if ((err = proc_dointvec(ctl, write, buffer, lenp, ppos)) != 0)
		return err;
	update_static_branch(old_enabled, &sysctl_tcp_estats_enabled);

	if ((estats_dent = estats_dir_dent()) == NULL)
		return 0;

	/* This is ugly and racy. */
	if ((cids =
	     kmalloc(tcp_estats_conn_num * sizeof(int), GFP_KERNEL)) == NULL)
		return -ENOMEM;
	n = get_connection_list(FIRST_CONNECTION_ENTRY, cids,
				tcp_estats_conn_num);
	for (i = 0; i < n; i++) {
		qstr.len = cid_to_str(cids[i], name);
		qstr.name = name;
		qstr.hash = full_name_hash(qstr.name, qstr.len);
		if ((conn_dent = d_lookup(estats_dent, &qstr)) != NULL) {
			for (fp = &estats_file_arr[0]; fp->name; fp++) {
				qstr.name = fp->name;
				qstr.len = fp->len;
				qstr.hash = full_name_hash(qstr.name, qstr.len);
				if ((dent = d_lookup(conn_dent, &qstr)) != NULL) {
					inode = dent->d_inode;
					if ((inode->i_mode = fp->mode) == 0)
						inode->i_mode =
						    S_IFREG |
						    sysctl_tcp_estats_fperms;
					inode->i_gid = sysctl_tcp_estats_gid;
					dput(dent);
				}
			}
			dput(conn_dent);
		}
	}
	dput(estats_dent);
	kfree(cids);

	return 0;
}

static int estats_proc_connection_revalidate(struct dentry *dentry,
					     struct nameidata *nd)
{
	int ret = 1;

	if (dentry->d_inode == NULL)
		return 0;
	read_lock_bh(&tcp_estats_linkage_lock);
	if (tcp_estats_lookup(cid_from_ino(dentry->d_inode->i_ino)) == NULL) {
		ret = 0;
		d_drop(dentry);
	}
	read_unlock_bh(&tcp_estats_linkage_lock);

	return ret;
}

static struct dentry_operations estats_dir_dentry_operations = {
      d_revalidate:estats_proc_connection_revalidate
};

static struct dentry *estats_dir_lookup(struct inode *dir,
					struct dentry *dentry,
					struct nameidata *nd)
{
	char *name;
	int len;
	int cid;
	unsigned c;
	struct inode *inode;
	unsigned long ino;
	struct tcp_estats *stats;

	if (proc_lookup(dir, dentry, nd) == NULL)
		return NULL;

	cid = 0;
	name = (char *)(dentry->d_name.name);
	len = dentry->d_name.len;
	if (len <= 0)		/* I don't think this can happen */
		return ERR_PTR(-EINVAL);
	while (len-- > 0) {
		c = *name - '0';
		name++;
		cid *= 10;
		cid += c;
		if (c > 9 || c < 0 || (cid == 0 && len != 0)) {
			cid = -1;
			break;
		}
	}
	if (cid < 0)
		return ERR_PTR(-ENOENT);

	read_lock_bh(&tcp_estats_linkage_lock);
	stats = tcp_estats_lookup(cid);
	if (stats == NULL || stats->estats_dead) {
		read_unlock_bh(&tcp_estats_linkage_lock);
		return ERR_PTR(-ENOENT);
	}
	read_unlock_bh(&tcp_estats_linkage_lock);

	ino = ino_from_cid(cid);
	inode = proc_estats_make_inode(dir->i_sb, ino);
	if (inode == NULL)
		return ERR_PTR(-ENOMEM);
	inode->i_nlink = 2;
	inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO;
	inode->i_flags |= S_IMMUTABLE;	/* ? */
	inode->i_op = &connection_dir_iops;
	inode->i_fop = &connection_dir_fops;

	dentry->d_op = &estats_dir_dentry_operations;
	d_add(dentry, inode);
	return NULL;
}

static struct file_operations estats_dir_fops = {
	.readdir = estats_dir_readdir
};

static struct inode_operations estats_dir_iops = {
	.lookup = estats_dir_lookup
};

/*
 * init
 */

int __init tcp_estats_proc_init(void)
{
	/* Set up the proc files. */
	proc_tcp_estats_dir = proc_mkdir("web100", NULL);
	proc_tcp_estats_dir->proc_iops = &estats_dir_iops;
	proc_tcp_estats_dir->proc_fops = &estats_dir_fops;

	proc_tcp_estats_header = create_proc_entry("header", S_IFREG | S_IRUGO,
						   proc_tcp_estats_dir);
	proc_tcp_estats_header->proc_fops = &header_file_operations;

	return 0;
}
