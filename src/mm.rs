//! Memory management routines


#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

#[inline]
pub unsafe fn read_phys<T>(paddr: PhysAddr) -> T {
    core::ptr::read_unaligned(paddr.0 as *const T)
}
