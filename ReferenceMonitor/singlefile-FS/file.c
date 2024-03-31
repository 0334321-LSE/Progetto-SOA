#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "singlefilefs.h"



ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    loff_t offset;
    int block_to_read;//index of the block to be read from device

    printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)",MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason

    //check that *off is within boundaries
    if (*off >= file_size)
        return 0;
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
	return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    return len - ret;

}

// This isn't usefull beacause kernel_write uses write_iter, but initially I don't know this so i leave it her.
// By checking kernel_write_iter documentation, kernel write doesn't work if exists "write" operation, must exists only write_iter
/* ssize_t onefilefs_write(struct file *filp, const char __user *buf, size_t len, loff_t *off) {
    struct inode *the_inode = filp->f_inode;
    struct super_block *sb = the_inode->i_sb;
    struct buffer_head *bh;
    int block_to_write;
    loff_t offset;
    uint64_t file_size = i_size_read(the_inode); // Using helper function to read the file size
    ssize_t ret;

    printk("%s: write operation called with len %ld - and offset %lld (the current file size is %lld)\n", MOD_NAME, len, *off, file_size);

    // Set the write offset to the end of the file
    *off = file_size;

    // Calculate the block index to write
  
    block_to_write = (file_size + DEFAULT_BLOCK_SIZE - 1) / DEFAULT_BLOCK_SIZE + 1; // Consider superblocco e inode

    printk("%s: write operation must access block %d of the device\n", MOD_NAME, block_to_write);

    // Read the block from disk
    bh = sb_bread(sb, block_to_write);
    if (!bh) {
        printk(KERN_ERR "%s: Error reading block %d\n", MOD_NAME, block_to_write);
        return -EIO; // I/O error
    }

    // Calculate the offset within the block
    offset = file_size % DEFAULT_BLOCK_SIZE;

    // Write data into the block buffer
    ret = simple_write_to_buffer(bh->b_data, sb->s_blocksize, &offset, buf, len);

    printk("%s: bytes written %ld starting from offset: %lld\n", MOD_NAME, ret, file_size);

    // Mark the buffer as dirty and synchronize it with disk
    mark_buffer_dirty(bh);
    sync_dirty_buffer(bh);
    brelse(bh);

    // Update offset
    the_inode->i_size += ret;

    return ret;
}
*/

ssize_t onefilefs_write_iter(struct kiocb *iocb, struct iov_iter *from) {
 // Access the file pointer and inode from the I/O control block
struct file *file = iocb->ki_filp;
struct inode *the_inode = file->f_inode;

// Get the current offset within the file
loff_t offset = file->f_pos;

// Retrieve the current size of the file
uint64_t file_size = i_size_read(the_inode);

// Variables to track block offset, block number to write, and buffer head
loff_t block_offset;
int block_to_write;
struct buffer_head *bh = NULL;

// Variable to store remaining space in the current block
size_t remaining_space_in_block;

// Variable to store the number of bytes copied from the iterator
size_t copied_bytes;

/* byte size of the payload */
size_t count = from->count;

// Allocate memory for the data buffer
char *data = kmalloc(count, GFP_KERNEL);
if (!data) {
    pr_err("%s: error in kmalloc allocation\n", MOD_NAME);
    return -ENOMEM;
}

// Copy data from the iterator to the data buffer
copied_bytes = _copy_from_iter((void *)data, count, from);
if (copied_bytes != count) {
    pr_err("%s: failed to copy %ld bytes from iov_iter\n", MOD_NAME, count);
    kfree(data);
    return -EFAULT;
}

// Update the file offset to the current size of the file
offset = file_size;

/* APPEND */
// Calculate the block offset within the current block
block_offset = offset % DEFAULT_BLOCK_SIZE;

// Calculate the block number to write, accounting for superblock and inode
block_to_write = offset / DEFAULT_BLOCK_SIZE + 2;

// Calculate the remaining space in the current block
remaining_space_in_block = DEFAULT_BLOCK_SIZE - block_offset;

// Check if the remaining space in the current block is insufficient for the data
if (remaining_space_in_block < count) {
    // Allocate a new block
    block_to_write++;
    bh = sb_bread(the_inode->i_sb, block_to_write);
    if (!bh) {
        kfree(data);
        return -EIO;
    }
    // Adjust the offset to the beginning of the new block
    offset = block_to_write * DEFAULT_BLOCK_SIZE;
    // Adjust the count to avoid writing beyond the block boundary
    count = min_t(size_t, count, DEFAULT_BLOCK_SIZE);
} else {
    // Read the existing block to write data into
    bh = sb_bread(the_inode->i_sb, block_to_write);
    if (!bh) {
        kfree(data);
        return -EIO;
    }
}

// Copy data into the block buffer at the appropriate offset
memcpy(bh->b_data + block_offset, data, count);

// Mark the buffer as dirty to indicate changes
mark_buffer_dirty(bh);

// Update the file size if necessary
if (offset + count > file_size)
    i_size_write(the_inode, offset + count);

// Release the buffer head
brelse(bh);

// Update the file offset
offset += count;

// Free the memory allocated for the data buffer
kfree(data);

// Update the file position
file->f_pos = offset;

// Return the number of bytes written
return count;

}


int onefilefs_open(struct inode *inode, struct file *file) {
    // Block open with O_CREAT or O_TRUNCT that can clean log content
    if (file->f_flags & (O_CREAT | O_TRUNC | O_WRITE | O_RDWR)) {
        printk("%s: Open blocked \n", MOD_NAME);
        return -EPERM;
    }

    // Restituisci 0 per indicare che l'apertura è avvenuta con successo
    return 0;
}

struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

	
	//get a locked inode from the cache 
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
       		 return ERR_PTR(-ENOMEM);

	//already cached inode - simply return successfully
	if(!(the_inode->i_state & I_NEW)){
		return child_dentry;
	}


    //this work is done if the inode was not already cached
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(5,12,0)
        inode_init_owner(the_inode, NULL, S_IFREG);
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)
        inode_init_owner(&init_user_ns,the_inode, NULL, S_IFREG);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
        inode_init_owner(&nop_mnt_idmap,the_inode, NULL, S_IFREG);
    #endif

	the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
	the_inode->i_op = &onefilefs_inode_ops;

	//just one link for this file
	set_nlink(the_inode,1);

	//now we retrieve the file size via the FS specific inode, putting it into the generic inode
    	bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
    	if(!bh){
		iput(the_inode);
		return ERR_PTR(-EIO);
    	}
	FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
	the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
	dget(child_dentry);

	//unlock the inode to make it usable 
    	unlock_new_inode(the_inode);

	return child_dentry;
    }

    return NULL;

}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .open = onefilefs_open,
    .write_iter = onefilefs_write_iter
};
