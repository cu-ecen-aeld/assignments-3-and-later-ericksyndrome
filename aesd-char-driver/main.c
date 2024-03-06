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
#include <linux/slab.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"

//#define INITIAL_BUFFER_SIZE 1024
#define INITIAL_BUFFER_SIZE 1000000
			
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Erick Reyes"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");
struct aesd_dev aesd_device;

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);



int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    PDEBUG("open");
    int mutex_result = 0;
    mutex_result = mutex_lock_interruptible(&aesd_device.lock); // Lock the mutex
    if (mutex_result != 0) {
    return -EINTR;
    // Handle the error (e.g., return an error code or perform cleanup)
    }
    // Get the device structure from the inode's private data
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev; // Store the device structure in the file's private data

    mutex_unlock(&aesd_device.lock); // Unlock the mutex

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    //struct aesd_dev *dev = filp->private_data; // Get the device structure
    int mutex_result = 0;
    mutex_result = mutex_lock_interruptible(&aesd_device.lock); // Lock the mutex
    if (mutex_result != 0) {
    return -EINTR;
    // Handle the error (e.g., return an error code or perform cleanup)
    }
    PDEBUG("release");
   
    // Optionally, you can also reset any other state or flags associated with this file descriptor

    mutex_unlock(&aesd_device.lock); // Unlock the mutex

    return 0; // Return 0 to indicate successful release
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data; // Get the device structure
    ssize_t retval = 0;
    size_t bytes_to_read;
    size_t entry_offset_byte;
    struct aesd_buffer_entry *entry;
    int mutex_result = 0;
    mutex_result = mutex_lock_interruptible(&aesd_device.lock); // Lock the mutex
    if (mutex_result != 0) {
    return -EINTR;
    // Handle the error (e.g., return an error code or perform cleanup)
    }

    PDEBUG("read %zu bytes with offset %lld", count,(long long) *f_pos);
    if (count > 1000)
    {
    	PDEBUG("long_string.txt contents %zu bytes with offset %lld", count, *buf);
    }

    // Find the buffer entry corresponding to the current file position
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(
                &dev->circular_buffer, *f_pos, &entry_offset_byte);
    if (!entry)
    {
    	PDEBUG("No more data to read for offset %lld", *f_pos);
    	mutex_unlock(&aesd_device.lock); // Unlock the mutex
        // No more data to read
        return 0;
    }

    // Determine the number of bytes to read from this entry
    bytes_to_read = entry->size - entry_offset_byte;
    if (bytes_to_read > count)
    {
        bytes_to_read = count;
    }

    // Copy data from the device's buffer to the user's buffer
    PDEBUG("Reading from circular buffer: %s", entry->buffptr + entry_offset_byte); // Print the buffer being read from the circular buffer
    if (copy_to_user(buf, entry->buffptr + entry_offset_byte, bytes_to_read))
    {
    	mutex_unlock(&aesd_device.lock); // Unlock the mutex
        // Failed to copy data to user space
        return -EFAULT;
    }

    // Update the file position and return value
    *f_pos += bytes_to_read;
    retval = bytes_to_read;

    mutex_unlock(&aesd_device.lock); // Unlock the mutex

    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence) {
    loff_t circ_buff_size = 0;
    loff_t ret_offset = -EINVAL;

    int index;
    struct aesd_buffer_entry *entry;

    if (mutex_lock_interruptible(&aesd_device.lock)) {
        return -EINTR;
    }

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buffer, index) {
        if(entry->buffptr) {
            circ_buff_size += entry->size;
        }
    }

    ret_offset = fixed_size_llseek(filp, off, whence, circ_buff_size);

    mutex_unlock(&aesd_device.lock);
    PDEBUG("llseek cmd=%d, buf size = %lld, offset_in = %lld, offset ret = %lld", 
        whence,
        circ_buff_size,
        off, 
        ret_offset);
    return ret_offset;
}


long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct aesd_seekto seek_data;
    struct aesd_dev *dev = filp->private_data;
    loff_t new_f_pos;
    
    PDEBUG("Inside of aesd_unlock_ioctl");
    printk(KERN_INFO "Inside aesd_unlocked_ioctl");
    
    // Copy the data from user space
    if (copy_from_user(&seek_data, (struct aesd_seekto *)arg, sizeof(seek_data))) {
        printk(KERN_ERR "Invalid command or offset");
        return -EFAULT;
    }
    printk(KERN_INFO "seek_data.write_cmd = %u", seek_data.write_cmd);
    printk(KERN_INFO "seek_data.write_cmd_offset = %u", seek_data.write_cmd_offset);
    PDEBUG("seek_data.write_cmd = %u", seek_data.write_cmd);
    PDEBUG("seek_data.write_cmd_offset = %u", seek_data.write_cmd_offset);

    // Calculate the new file position
    int byte_pos = 0;
    int arr_pos = 0;
    int pos_count = 0;
    int arr_end = 0;

    // Check if the command is valid
    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) {
        PDEBUG("Error - Invalid ioctl command type. Expected: %d, Actual: %d", AESD_IOC_MAGIC, _IOC_TYPE(cmd));
        printk(KERN_ERR "Error - Invalid ioctl command type. Expected: %d, Actual: %d", AESD_IOC_MAGIC, _IOC_TYPE(cmd));
        return -ENOTTY;
    }

    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) {
        PDEBUG("Error - Invalid ioctl command number. Maximum allowed: %d, Actual: %d", AESDCHAR_IOC_MAXNR, _IOC_NR(cmd));
        printk(KERN_ERR "Error - Invalid ioctl command number. Maximum allowed: %d, Actual: %d", AESDCHAR_IOC_MAXNR, _IOC_NR(cmd));
        return -ENOTTY;
    }

    switch (cmd) {
        case AESDCHAR_IOCSEEKTO:
           /* // Copy the data from user space
            if (copy_from_user(&seek_data, (struct aesd_seekto *)arg, sizeof(seek_data))) {
                printk(KERN_ERR "Invalid command or offset");
                return -EFAULT;
            }
	     */
            // Calculate the new file position
            //int byte_pos = 0;
            //int arr_pos = 0;
            //int pos_count = 0;
            arr_end = dev->circular_buffer.out_offs + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
            /*
            for (int i = dev->circular_buffer.out_offs; i < arr_end; i++) {
                arr_pos = i % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
                if (pos_count == seek_data.write_cmd) break;
                byte_pos += dev->circular_buffer.entry[arr_pos].size;
                pos_count++;
            }
            */
            //new_f_pos = byte_pos + seek_data.write_cmd_offset;
	    new_f_pos = dev->circular_buffer.entry[seek_data.write_cmd].size * seek_data.write_cmd + seek_data.write_cmd_offset;
            // Update the file position
            filp->f_pos = new_f_pos;
            printk(KERN_INFO "New file position set to %lld", (long long) new_f_pos);
            break;
        default:
            printk(KERN_ERR "Invalid command");
            return -ENOTTY;
    }
    cmd = 0;
    arg = 0;
    return 0;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .unlocked_ioctl = aesd_unlocked_ioctl,
     .llseek = aesd_llseek,
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


ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    char *kern_buf;
    struct aesd_buffer_entry new_entry;
    
    // Mutex Locking with Interrupt Handling
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

   

    // Memory Allocationaesd_ioctl.h
    kern_buf = kzalloc(count, GFP_KERNEL); // Removed +1 as we're not relying on null-terminator
    //kern_buf = kzalloc(20000, GFP_KERNEL); // Removed +1 as we're not relying on null-terminator
    if (!kern_buf) {
        PDEBUG("Failed to allocate kernel buffer");
        retval = -ENOMEM;
        goto out_unlock;
    }

    // Copying data from user space to kernel space
    if (copy_from_user(kern_buf, buf, count)) {
        PDEBUG("Failed to copy from user");
        retval = -EFAULT;
        goto out_free;
    }


       PDEBUG("kern_buff contents (kernal space): %zu bytes with offset %s", count, kern_buf);


    // Checking for the presence of a newline character
    if (kern_buf[count - 1] == '\n') {
        if (dev->temp_buffer) {
            size_t new_size = dev->temp_size + count;
            char *combined_buf = krealloc(dev->temp_buffer, new_size, GFP_KERNEL);
            if (!combined_buf) {
                PDEBUG("Failed to allocate combined buffer");
                retval = -ENOMEM;
                goto out_free;
            }

            memcpy(combined_buf + dev->temp_size, kern_buf, count);

            //kfree(kern_buf);
            kern_buf = NULL;
            kern_buf = combined_buf;
            count = new_size; 
            dev->temp_buffer = NULL;
            dev->temp_size = 0;
        }

        new_entry.buffptr = kern_buf;
        new_entry.size = count;

        PDEBUG("Adding to circular buffer: %s", kern_buf);
	
        if (dev->circular_buffer.full) {
            PDEBUG("Circular buffer is full, freeing oldest entry");
            kfree(dev->circular_buffer.entry[dev->circular_buffer.out_offs].buffptr);
        }
	
        aesd_circular_buffer_add_entry(&dev->circular_buffer, &new_entry);

        retval = count;
    } else {
        PDEBUG("Write is unterminated, saving for next write operation");
        if (dev->temp_size) {
            PDEBUG("temp_buff exist adding too it...");
            size_t new_size = dev->temp_size + count;
            char *combined_buf = krealloc(dev->temp_buffer, new_size + 1, GFP_KERNEL);
            combined_buf[new_size] = '\0';
            if (!combined_buf) {
                PDEBUG("Failed to allocate combined buffer");
                retval = -ENOMEM;
                goto out_free;
            }

            memcpy(combined_buf + dev->temp_size, kern_buf, count);

            kfree(kern_buf);
            kern_buf = NULL;
            dev->temp_buffer = combined_buf;
            PDEBUG("temp_buffer contents: %s", dev->temp_buffer);
            dev->temp_size = new_size; 
        } else {
            PDEBUG("Creating Temp buffer...");
            dev->temp_buffer = kern_buf;
            dev->temp_size = count;
            PDEBUG("temp_buffer contents, brand new: %s", dev->temp_buffer);
            kern_buf = NULL; // Transfer ownership to avoid double-free
        }
    }
    PDEBUG("Leaving write function..");
    mutex_unlock(&dev->lock);
    return retval;

out_free:
    kfree(kern_buf);
out_unlock:
    mutex_unlock(&dev->lock);
    return retval;
}


int aesd_init_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entry;
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
    // In aesd_init_module()
    mutex_init(&aesd_device.lock);
    /**
     * TODO: initialize the AESD specific portion of the device
     */
     // Initialize the circular buffer
    aesd_circular_buffer_init(&aesd_device.circular_buffer);

    // Dynamically allocate memory for each buffer entry using kmalloc
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buffer, index) {
        entry->buffptr = kzalloc(INITIAL_BUFFER_SIZE, GFP_KERNEL);
        if (!entry->buffptr) {
            printk(KERN_ERR "Failed to allocate memory for buffer entry %d\n", index);
            while (index--) {
                kfree(aesd_device.circular_buffer.entry[index].buffptr);
            }
            unregister_chrdev_region(dev, 1);
            return -ENOMEM;
        }
        entry->size = 0;
    }
    
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

    // Unregister the character device region
    unregister_chrdev_region(devno, 1);

    // Delete the cdev structure
    cdev_del(&aesd_device.cdev);

    // Cleanup AESD specific portions
    // Free any memory associated with the circular buffer entries
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buffer, index) {
        if (entry->buffptr) {
            kfree(entry->buffptr); // Free the memory associated with each buffer entry
            entry->buffptr = NULL; // Reset the pointer
        }
    }

    // Optionally, if there's a temporary buffer, free it
    if (aesd_device.temp_buffer) {
        kfree(aesd_device.temp_buffer);
        aesd_device.temp_buffer = NULL; // Reset the pointer
    }

    // Optionally, destroy any locks or synchronization primitives
    mutex_destroy(&aesd_device.lock);
}


module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
