/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/mutex.h>
#include <linux/slab.h>
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Erick Reyes"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    
    struct aesd_dev *dev;
    PDEBUG("open");
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * Nothing to do here
     */
     
     
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev* dev = (struct aesd_dev*)filp->private_data;
    struct aesd_buffer_entry *entry = NULL;
    ssize_t retval = 0;
    size_t bytes_remaining = 0; //checks if not copied
    size_t entry_offset = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    
    //if this is 1 then retstart system
    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
		
	//check if buff or buffer	
	entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buff, *f_pos, &entry_offset);
	
	if (entry == NULL) {
		mutex_unlock(&dev->lock);
		return 0; // no entry so nothing to read
	}
	
	//to prevent reading more than what is available in the entry, question
	if (count > entry->size - entry_offset) 
		count = entry->size - entry_offset;
	
	
	bytes_remaining = copy_to_user(buf, &entry->buffptr[entry_offset], count);
	if (bytes_remaining != 0) {
		retval = -EFAULT;
	}
	else {
		*f_pos += count; //update file position
		retval = count;
	}
	mutex_unlock(&dev->lock);     
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev* dev = (struct aesd_dev*)filp->private_data;
    ssize_t retval = -ENOMEM;
    size_t copied_bytes = 0;
    int newline = 0;
    size_t i;   
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
	
	//allocating buffer or expanding as needed
	if (dev->w_buff == NULL) {
		dev->w_buff = kmalloc(count, GFP_KERNEL);
		if (!dev->w_buff) {
			mutex_unlock(&dev->lock);
			return -ENOMEM;
		}
		dev->w_buff_size = count;
		retval = count;
	}
	
	// dont need to use kfree(dev->w_buff) as krealloc does this for me
	// if it moves buffer to a new location 
	else {
		char *new_buff = krealloc(dev->w_buff, dev->w_buff_size + count, GFP_KERNEL);
		if (!new_buff) {
			mutex_unlock(&dev->lock);
			return -ENOMEM;
		}
		dev->w_buff = new_buff;
		//dev->w_buff_size += count;
		retval = count;
	}
	//void casting to not worry about type and just copy data to it
	copied_bytes = copy_from_user((void *)&dev->w_buff[dev->w_buff_size - count], buf, count);
	if (copied_bytes != 0) {
		retval = -EFAULT;
	}
	
	else { //checking for newline
		for (i = 0; i < count; i++) {
			if (dev->w_buff[dev->w_buff_size - count + i] == '\n')
			{
				newline = true;
				break;
			}
		}
	}
	
	// if newline found add to circular buffer
	if (newline) {
		struct aesd_buffer_entry new_entry = { .buffptr = dev->w_buff, .size = dev->w_buff_size };
		aesd_circular_buffer_add_entry(&dev->buff, &new_entry);
		
		//reset for next write
		dev->w_buff = NULL;
		dev->w_buff_size = 0;
		}
	mutex_unlock(&dev->lock);
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    
    aesd_device.w_buff = NULL;
    aesd_device.w_buff_size = 0;
    aesd_circular_buffer_init(&aesd_device.buff);
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    uint8_t index;
    struct aesd_buffer_entry *entry;

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    //freeing write buffer
    if (aesd_device.w_buff) {
		kfree(aesd_device.w_buff);
		aesd_device.w_buff = NULL;
	}
	
	// manually freeing each allocated buffer entry
	
	
	//check again
	AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buff, index) {
		if (entry->buffptr != NULL) {
			kfree((void *)entry->buffptr);
			//entry->buffptr == NULL;
		}
	}

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
