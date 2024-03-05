/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
	// initialize variables for offsets
	// keeps track of where we are in this continous block of data
	size_t current_offset = 0;
	size_t entry_size = 0;
	// sets the entry ptr as zero intially
	struct aesd_buffer_entry *entry = NULL;
	
	// checks if buffer is valid or not full
	if (buffer == NULL) return NULL;
	
	// looping for entry
	for (uint8_t i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
		
		// first location in entry to read from plus i iteration from a range of 10
		uint8_t index = (buffer->out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
		
		//entry defined above is now getting the entry from the array index that was defined in the CB struct
		entry = &buffer->entry[index];
		
		//crucial bc ensures that buffer doesnt access entries where buffer isn't full yet
		if (!buffer->full && buffer->in_offs) break;
		
		// size is number of bytes stored in buffptr
		entry_size = entry->size;
		
		if (char_offset < (current_offset + entry_size)) {
			
			//this shows we found our entry point containing the offset
			*entry_offset_byte_rtn = char_offset - current_offset;
			return entry;
		}
		current_offset += entry_size;
	}
			
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
	//check if buffer is full
	//if not then add the entry 
	//overwrite old entry then increment to new start or entry
	
	// full variable retrieved from struct in header file
	if (buffer->full) {
		
		//advances out_offs to next location and wraps around if exceeds CB
		buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	}
	
	//copy the add_entry to the current in_offs position
	buffer->entry[buffer->in_offs] = *add_entry;
	
	//advance the in_offs to the next position and wrapping if needed
	// remember that in_offs is the current location in the entry structure where the next write should
    //be stored.
	buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	
	//checking if buffer is full, keep in mind that when in_offs = out_offs means that the
	//in_offs has wrapped around to overlap with out_offs
	if(buffer->in_offs == buffer->out_offs) {
		buffer->full = true;
	}
}
	

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
