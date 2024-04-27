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

#define KERNEL_CODE

#include "singlefilefs.h"

/*
// Acquire inode lock
static inline void lock_inode(struct inode *inode) {
    spin_lock(&inode->i_lock);
}

// Release inode lock
static inline void unlock_inode(struct inode *inode) {
    spin_unlock(&inode->i_lock);
}
*/

ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size;
    int ret;
    loff_t block_offset;
    int block_to_write;//index of the block to be read from device
    
    //printk("%s: read operation called with len %ld - and block_offset %lld (the current file size is %lld)",MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason

    read_lock(&log_rwlock);
    //lock_inode(the_inode);
    file_size = the_inode->i_size;

    //check that *off is within boundaries
    if (*off >= file_size){
        read_unlock(&log_rwlock);
        //unlock_inode(the_inode);
        return 0;
    }
        
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level block_offset for the operation
    block_offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (block_offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - block_offset;

    //compute the actual index of the the block to be read from device
    block_to_write = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 aclens for superblock and file-inode on device
    
    //printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_write);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_write);
    if(!bh){
        read_unlock(&log_rwlock);
	    //unlock_inode(the_inode);
        return -EIO;
    }

    ret = copy_to_user(buf,bh->b_data + block_offset, len);
    *off += (len - ret);
    brelse(bh); 
    read_unlock(&log_rwlock);    
    //unlock_inode(the_inode);

    return len - ret;

}

ssize_t onefilefs_write_iter(struct kiocb *iocb, struct iov_iter *from) {
    // Access the file pointer and inode from the I/O control block
    struct file *file = iocb->ki_filp;
    struct inode *the_inode = file->f_inode;

    // data to be written
    char *data = from->kvec->iov_base; 

    // byte size of the payload 
    size_t len = from->kvec->iov_len;

    // Get the current block_offset within the file
    loff_t block_offset;

    // Current size of the file
    uint64_t file_size;
    
    uint64_t offset;


    // Variables to track: block number to write, and buffer head
    int block_to_write;
    struct buffer_head *bh = NULL;

    // Variable to store remaining space in the current block
    size_t remaining_space_in_block;
 
    //Get the lock
    write_lock(&log_rwlock);
    
     //  APPEND STARTS 
    // Get the current offset within the file
    file_size = i_size_read(the_inode);

    offset = file_size;

    // the relative offset inside the block
    block_offset = offset % DEFAULT_BLOCK_SIZE;
    
    // Calculate the block number; +2 for superblock and inode
    block_to_write = offset / DEFAULT_BLOCK_SIZE + 2;

    // Calculate the remaining space in the current block
    remaining_space_in_block = DEFAULT_BLOCK_SIZE - block_offset;

    //printk("%s: Space %ld - %ld", MOD_NAME, remaining_space_in_block, len);

    // Check if the remaining space in the current block is insufficient for the data
    if (remaining_space_in_block <= len) {
        printk("%s: Insufficient space, allocate new block", MOD_NAME);
        bh = (struct buffer_head *)sb_bread(the_inode->i_sb, block_to_write);
          if (!bh) {
            //Free the lock
            write_unlock(&log_rwlock);
            return -EIO;
        }
        
        // Fill the remaining space in the block with blank spaces
        memset(bh->b_data + block_offset, ' ', remaining_space_in_block);
        brelse(bh);


        // Adjust the offset and the block_offset to the beginning of the new block
        offset += remaining_space_in_block;
        block_offset = 0;
        // Go ahead to new block
        block_to_write++;
    }


    bh = (struct buffer_head *)sb_bread(the_inode->i_sb, block_to_write);
    if (!bh) {
        //Free the lock
        write_unlock(&log_rwlock);
        return -EIO;
    }

    // Copy data into the block buffer at the appropriate block_offset
    memcpy(bh->b_data + block_offset, data, len);

    // Mark the buffer as dirty to schedule it for writing back to the disk
    mark_buffer_dirty(bh);

    // Update the file size if necessary
    if (offset + len > file_size)
        i_size_write(the_inode, offset + len);

    block_offset += len;

    // Update the file pos\ition
    file->f_pos = offset;

    //Free the lock
    write_unlock(&log_rwlock);
    
    // Release the buffer head
    brelse(bh);
    
    // Return the number of bytes written
    return len;

}

int onefilefs_open(struct inode *inode, struct file *file) {

    // Block open with O_CREAT or O_TRUNCT that can remove log content
    if (file->f_flags & (O_CREAT | O_TRUNC)) {
        printk("%s: Open blocked \n", MOD_NAME);
        return -EPERM;
    }

    return 0;
}

struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    //printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

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
