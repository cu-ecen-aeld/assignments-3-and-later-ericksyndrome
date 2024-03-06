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
    size_t accumulated_byte_count = 0; // Accumulator for the byte count traversed so far
    size_t i,j;
    // Loop to traverse the circular buffer entries
    for(i = buffer->out_offs, j=0 ; ((i != buffer->in_offs) || buffer->full) && (j<10) ; j++)
    {
        // Check if the character offset falls within this buffer entry
        if((accumulated_byte_count + buffer->entry[i].size) > char_offset)
        {
            // Calculate the byte offset within this entry and return this entry
            *entry_offset_byte_rtn = char_offset - accumulated_byte_count;
            return &buffer->entry[i];
        }
        
        // Update the accumulated byte count
        accumulated_byte_count += buffer->entry[i].size;
        
        // Circularly increment the index for the next iteration
        i = (i + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    
    return NULL; // Return NULL if the specified character offset is not found in the buffer
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in 
* @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
* 
* @return NULL or, if an existing entry at out_offs was replaced, 
*           the value of buffptr for the entry which was replaced (for use with dynamic memory allocation/free)
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    // Validate the input parameters; exit if either is NULL
    if(!add_entry || !buffer) {
        return;
    }

    // Add the new entry at the current "in" index
    buffer->entry[buffer->in_offs] = *add_entry;

    // Increment the "in" index and wrap around if necessary
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    // If the buffer is full, update the "out" index to the new start
    if(buffer->full) {
        buffer->out_offs = buffer->in_offs;
    }

    // Update the buffer's "full" status flag
    buffer->full = (buffer->in_offs == buffer->out_offs);
}


/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
