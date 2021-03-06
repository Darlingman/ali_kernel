#ifdef CONFIG_EXT3_FS_SUBTREE

#include <linux/xattr.h>
#include <linux/fs.h>

extern int ext3_subtree_xattr_read(struct inode *inode, unsigned int *subtree);
extern int ext3_subtree_xattr_write(handle_t *handle, struct inode *inode,
				    unsigned int subtree, int xflags);
extern int ext3_subtree_init(handle_t *handle, struct inode *inode);
extern int ext3_subtree_read(struct inode *inode);
extern int ext3_subtree_change(struct inode *inode, unsigned int new_subtree);
static inline u32 ext3_get_subtree(struct inode *inode)
{
	return EXT3_I(inode)->i_subtree;
}
static inline void ext3_set_subtree(struct inode *inode, u32 id)
{
	EXT3_I(inode)->i_subtree = id;
}
#else /* !CONFIG_EXT3_FS_SUBTREE */
#define ext3_set_subtree(inode, id) do {} while (0)
static inline u32 ext3_get_subtree(struct inode *inode)
{
	return 0;
}
static inline int ext3_subtree_xattr_read(struct inode *inode, unsigned int *id)
{
	return -ENOTSUPP;
}
static inline int ext3_subtree_init(handle_t *handle, struct inode *inode)
{
	return 0;
}
static inline int ext3_subtree_read(struct inode *inode)
{
	return 0;
}
static inline int ext3_subtree_change(struct inode *inode, unsigned int id)
{
	return -ENOTSUPP;
}
#endif /* CONFIG_EXT3_FS_SUBTREE */
