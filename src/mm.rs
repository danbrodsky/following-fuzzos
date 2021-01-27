//! Memory management routines

use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

/// slice of physical memory
pub struct PhysSlice(PhysAddr, usize);

impl PhysSlice {
    /// Create a new slice to physical memory
    pub unsafe fn new(addr: PhysAddr, size: usize) -> Self {

        // make sure there is no integer overflow
        // if  size > 0 && addr.0.checked_add(size as u64).is_none() {
        //     return Err(());
        // }
        PhysSlice(addr, size)
    }

    pub fn len(&self) -> usize {
        self.1
    }

    /// Discord `bytes` from front of the slice by updating pointer and length
    pub fn discard(&mut self, bytes: usize) -> Result<(), ()> {
        if self.1 >= bytes {
            (self.0).0 += bytes as u64;
            self.1     -= bytes;
            Ok(())
        } else {
            Err(())
        }
    }


    /// Read a `T` from the slice, updating the ptr
    pub unsafe fn consume<T>(&mut self) -> Result<T, ()> {
        if self.1 < size_of::<T>() {
            return Err(());
        }

        let data = read_phys_unaligned::<T>(self.0);
        self.discard(size_of::<T>())?;

        Ok(data)

        // compute the pointer to the mem at slice
    }
}

#[inline]
pub unsafe fn read_phys<T>(paddr: PhysAddr) -> T {
    core::ptr::read(paddr.0 as *const T)
}

#[inline]
pub unsafe fn read_phys_unaligned<T>(paddr: PhysAddr) -> T {
    core::ptr::read_unaligned(paddr.0 as *const T)
}
