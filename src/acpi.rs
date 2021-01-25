//! An very lightweight ACPI implementation for extracting basic information
//! about CPU topography and NUMA memory regions

use core::mem::size_of;
// use core::sync::atomic::{AtomicU32, Ordering, AtomicU8};
// use core::convert::TryInto;
use crate::mm::{self, PhysAddr};
use crate::efi;
// use alloc::vec::Vec;
// use alloc::collections::BTreeMap;

/// Maximum number of cores allowed on the system
pub const MAX_CORES: usize = 1024;


/// In-memory representation of an RSDP ACPI structure
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Rsdp {
    signature:  [u8; 8],
    checksum:   u8,
    oem_id:     [u8; 6],
    revision:   u8,
    rsdt_addr:  u32,
    length:     u32,
    xsdt_addr:  u64,
    extended_checksum: u8,
    reversed: [u8; 3]
}

/// In-memory representation of an Extended RSDP ACPI structure
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct RsdpExtended {
    descriptor:        Rsdp,
    length:            u32,
    xsdt_addr:         u64,
    extended_checksum: u8,
    reserved:          [u8; 3],
}

impl Rsdp {
    /// Load an RSDP struct from `addr`
    unsafe fn from_addr(addr: PhysAddr) -> Result<Self> {
        // read base RSDP struct
        let rsdp = mm::read_phys::<Rsdp>(addr);

        Ok(rsdp)
    }
}


impl RsdpExtended {
    /// Load an Extended RSDP struct from `addr`
    unsafe fn from_addr(addr: PhysAddr) -> Result<Self> {
        // read base RSDP struct
        panic!();
        // let rsdp = mm::read_phys<RsdpExtended>(addr);
        let rsdp = mm::read_phys::<Rsdp>(addr);
    }
}


/// In-memory representation of an ACPI table header
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Header {
    signature:        [u8; 4],
    length:           u32,
    revision:         u8,
    checksum:         u8,
    oemid:            [u8; 6],
    oem_table_id:     u64,
    oem_revision:     u32,
    creator_id:       u32,
    creator_revision: u32,
}

/// Parse a standard ACPI table header. This will parse out the header,
/// validate the checksum and length, and return a physical address and size
/// of the payload following the header.
unsafe fn parse_header(addr: PhysAddr) -> (Header, PhysAddr, usize) {
    // Read the header
    let head = mm::read_phys::<Header>(addr);

    // Get the number of bytes for the table
    let payload_len = head.length
        .checked_sub(size_of::<Header>() as u32)
        .expect("Integer underflow on table length");

    // Check the checksum for the table
    let sum = (addr.0..addr.0 + head.length as u64)
        .fold(0u8, |acc, paddr| {
            acc.wrapping_add(mm::read_phys(PhysAddr(paddr as u64)))
        });
    assert!(sum == 0, "Table checksum invalid {:?}",
            core::str::from_utf8(&head.signature));

    // Return the parsed header
    (head, PhysAddr(addr.0 + size_of::<Header>() as u64), payload_len as usize)
}

/// result types which wraps ACPI error
type Result<T> = core::result::Result<T, Error>;


/// Errors from ACPI table parsing
pub enum Error {
    /// ACPI table not reported by UEFI
    RsdpNotFound,
}

/// Initialize the ACPI subsystem. Mainly looking for APICs and memory maps.
/// Brings up all cores on the system
pub unsafe fn init() -> Result<()> {



    let rsdp_addr = efi::get_acpi_table()
        .ok_or(Error::RsdpNotFound)?;
    // let rsdp = core::ptr::read_unaligned(rsdp_addr as *const Rsdp);

    let rsdp = RsdpExtended::from_addr(PhysAddr(rsdp_addr as u64))?;

    Ok(())
}

//     assert!(rsdp.revision >= 1, "Minimum ACPI version 2.0 required");
//     assert!(rsdp.length as usize >= size_of::<Rsdp>(), "RSP size invalid");


//     let (xsdt, xsdt_payload, xsdt_size) = parse_header(PhysAddr(rsdp.xsdt_addr));

//     assert!(&xsdt.signature == b"XSDT", "XSDT signature mismatch");
//     assert!((xsdt_size % size_of::<u64>()) == 0, "Invalid table size for XSDT");

//     let xsdt_entries = xsdt_size / size_of::<u64>();

//     // Set up the structures we're interested as parsing out as `None` as some
//     // of them may or may not be present.
//     // let mut apics          = None;
//     // let mut apic_domains   = None;
//     // let mut memory_domains = None;

//     // Go through each table described by the RSDT
//     for entry in 0..xsdt_entries {
//         // Get the physical address of the RSDP table entry
//         let entry_paddr = xsdt_payload.0 as usize + entry * size_of::<u64>();

//         // Get the pointer to the table
//         let table_ptr: u64 = mm::read_phys(PhysAddr(entry_paddr as u64));

//         // Get the signature for the table
//         let signature: [u8; 4] = mm::read_phys(PhysAddr(table_ptr as u64));

//         if &signature == b"APIC" {
//             // Parse the MADT
//             // assert!(apics.is_none(), "Multiple MADT ACPI table entries");
//             parse_madt(PhysAddr(table_ptr as u64));
//         }
//             // // Parse the SRAT
//             // assert!(apic_domains.is_none() && memory_domains.is_none(),
//             //     "Multiple SRAT ACPI table entries");
//         else if &signature == b"SRAT" {
//             parse_srat(PhysAddr(table_ptr as u64));
//         }
//             // apic_domains   = Some(ad);
//             // memory_domains = Some(md);
//     }

//     // if let (Some(ad), Some(md)) = (apic_domains, memory_domains) {
//     //     // Register APIC to domain mappings
//     //     for (&apic, &node) in ad.iter() {
//     //         APIC_TO_DOMAIN[apic as usize].store(node.try_into().unwrap(),
//     //             Ordering::Relaxed);
//     //     }

//     //     // Notify the memory manager of the known APIC -> NUMA mappings
//     //     crate::mm::register_numa_nodes(ad, md);
//     // }

//     // // Set the total core count based on the number of detected APICs on the
//     // // system. If no APICs were mentioned by ACPI, then we can simply say there
//     // // is only one core.
//     // TOTAL_CORES.store(apics.as_ref().map(|x| x.len() as u32).unwrap_or(1),
//     //                   Ordering::SeqCst);

//     // // Initialize the state of all the known APICs
//     // if let Some(apics) = &apics {
//     //     for &apic_id in apics {
//     //         APICS[apic_id as usize].store(ApicState::Offline as u8,
//     //                                       Ordering::SeqCst);
//     //     }
//     // }

//     // // Set that our core is online
//     // APICS[core!().apic_id().unwrap() as usize]
//     //     .store(ApicState::Online as u8, Ordering::SeqCst);

//     // // Launch all other cores
//     // if let Some(valid_apics) = apics {
//     //     // Get exclusive access to the APIC for this core
//     //     let mut apic = core!().apic().lock();
//     //     let apic = apic.as_mut().unwrap();

//     //     // Go through all APICs on the system
//     //     for apic_id in valid_apics {
//     //         // We don't want to start ourselves
//     //         if core!().apic_id().unwrap() == apic_id { continue; }

//     //         // Mark the core as launched
//     //         set_core_state(apic_id, ApicState::Launched);

//     //         // Launch the core
//     //         apic.ipi(apic_id, 0x4500);
//     //         apic.ipi(apic_id, 0x4608);
//     //         apic.ipi(apic_id, 0x4608);

//     //         // Wait for the core to come online
//     //         while core_state(apic_id) != ApicState::Online {}
//     //     }
//     // }
// }

// /// Parse the MADT out of the ACPI tables
// /// Returns a vector of all usable APIC IDs
// unsafe fn parse_madt(ptr: PhysAddr) {
//     // Parse the MADT header
//     let (_header, payload, size) = parse_header(ptr);

//     // Skip the local interrupt controller address and the flags to get the
//     // physical address of the ICS
//     let mut ics = PhysAddr(payload.0 + 4 + 4);
//     let end = payload.0 + size as u64;

//     // Create a new structure to hold the APICs that are usable
//     // let mut apics = Vec::new();

//     loop {
//         /// Processor is ready for use
//         const APIC_ENABLED: u32 = 1 << 0;

//         /// Processor may be enabled at runtime (IFF ENABLED is zero),
//         /// otherwise this bit is RAZ
//         const APIC_ONLINE_CAPABLE: u32 = 1 << 1;

//         // Make sure there's room for the type and the length
//         if ics.0 + 2 > end { break; }

//         // Parse out the type and the length of the ICS entry
//         let typ: u8 = mm::read_phys(PhysAddr(ics.0 + 0));
//         let len: u8 = mm::read_phys(PhysAddr(ics.0 + 1));

//         // Make sure there's room for this structure
//         if ics.0 + len as u64 > end { break; }
//         assert!(len >= 2, "Bad length for MADT ICS entry");

//         match typ {
//             0 => {
//                 // LAPIC entry
//                 assert!(len == 8, "Invalid LAPIC ICS entry");

//                 // Read the APIC ID
//                 let apic_id: u8  = mm::read_phys(PhysAddr(ics.0 + 3));
//                 let flags:   u32 = mm::read_phys(PhysAddr(ics.0 + 4));

//                 // If the processor is enabled, or can be enabled, log it as
//                 // a valid APIC
//                 if (flags & APIC_ENABLED) != 0 ||
//                         (flags & APIC_ONLINE_CAPABLE) != 0 {
//                             print!("found lapic {:#x}\n", apic_id);
//                     // apics.push(apic_id as u32);
//                 }
//             }
//             9 => {
//                 // x2apic entry
//                 assert!(len == 16, "Invalid x2apic ICS entry");

//                 // Read the APIC ID
//                 let apic_id: u32 = mm::read_phys(PhysAddr(ics.0 + 4));
//                 let flags:   u32 = mm::read_phys(PhysAddr(ics.0 + 8));

//                 // If the processor is enabled, or can be enabled, log it as
//                 // a valid APIC
//                 if (flags & APIC_ENABLED) != 0 ||
//                         (flags & APIC_ONLINE_CAPABLE) != 0 {
//                     // apics.push(apic_id);
//                 }
//             }
//             _ => {
//                 // Don't really care for now
//             }
//         }

//         // Go to the next ICS entry
//         ics = PhysAddr(ics.0 + len as u64);
//     }

//     // apics
// }

// /// Parse the SRAT out of the ACPI tables
// /// Returns a tuple of (apic -> domain, memory domain -> phys_ranges)
// unsafe fn parse_srat(ptr: PhysAddr) {
//     // Parse the SRAT header
//     let (_header, payload, size) = parse_header(ptr);

//     // Skip the 12 reserved bytes to get to the SRA structure
//     let mut sra = PhysAddr(payload.0 + 4 + 8);
//     let end = payload.0 + size as u64;

//     // Mapping of proximity domains to their memory ranges
//     // let mut memory_affinities:
//     //     BTreeMap<u32, RangeSet> = BTreeMap::new();

//     // Mapping of APICs to their proximity domains
//     // let mut apic_affinities: BTreeMap<u32, u32> = BTreeMap::new();

//     loop {
//         /// The entry is enabled and present. Some BIOSes may staticially
//         /// allocate these table regions, thus the flags indicate whether the
//         /// entry is actually present or not.
//         const FLAGS_ENABLED: u32 = 1 << 0;

//         // Make sure there's room for the type and the length
//         if sra.0 + 2 > end { break; }

//         // Parse out the type and the length of the ICS entry
//         let typ: u8 = mm::read_phys(PhysAddr(sra.0 + 0));
//         let len: u8 = mm::read_phys(PhysAddr(sra.0 + 1));

//         // Make sure there's room for this structure
//         if sra.0 + len as u64 > end { break; }
//         assert!(len >= 2, "Bad length for SRAT SRA entry");

//         match typ {
//             0 => {
//                 // Local APIC
//                 assert!(len == 16, "Invalid APIC SRA entry");

//                 // Extract the fields we care about
//                 let domain_low:  u8      = mm::read_phys(PhysAddr(sra.0 + 2));
//                 let domain_high: [u8; 3] = mm::read_phys(PhysAddr(sra.0 + 9));
//                 let apic_id:     u8      = mm::read_phys(PhysAddr(sra.0 + 3));
//                 let flags:       u32     = mm::read_phys(PhysAddr(sra.0 + 4));

//                 // Parse the domain low and high parts into an actual `u32`
//                 let domain = [domain_low,
//                     domain_high[0], domain_high[1], domain_high[2]];
//                 let domain = u32::from_le_bytes(domain);

//                 // Log the affinity record
//                 if (flags & FLAGS_ENABLED) != 0 {
//                     print!("APIC {:x} -> domain {:#x}\n", apic_id, domain);
//                     // assert!(apic_affinities.insert(apic_id as u32, domain)
//                     //         .is_none(), "Duplicate LAPIC affinity domain");
//                 }
//             }
//             1 => {
//                 // Memory affinity
//                 assert!(len == 40, "Invalid memory affinity SRA entry");

//                 // Extract the fields we care about
//                 let domain: u32      = mm::read_phys(PhysAddr(sra.0 +  2));
//                 let base:   PhysAddr = mm::read_phys(PhysAddr(sra.0 +  8));
//                 let size:   u64      = mm::read_phys(PhysAddr(sra.0 + 16));
//                 let flags:  u32      = mm::read_phys(PhysAddr(sra.0 + 28));

//                 // Only process ranges with a non-zero size (observed on
//                 // polar and grizzly that some ranges were 0 size)
//                 if size > 0 {
//                     // Log the affinity record
//                     if (flags & FLAGS_ENABLED) != 0 {

//                         print!("Domain {:x} -> {:#x}-{:#x}\n",
//                                domain,
//                                base.0,
//                                base.0 + (size - 1));
//                         // memory_affinities.entry(domain).or_insert_with(|| {
//                         //     RangeSet::new()
//                         // }).insert(Range {
//                         //     start: base.0,
//                         //     end:   base.0.checked_add(size.checked_sub(1)
//                         //                               .unwrap()).unwrap()
//                         // });
//                     }
//                 }
//             }
//             2 => {
//                 // Local x2apic
//                 assert!(len == 24, "Invalid x2apic SRA entry");

//                 // Extract the fields we care about
//                 let domain:  u32 = mm::read_phys(PhysAddr(sra.0 +  4));
//                 let apic_id: u32 = mm::read_phys(PhysAddr(sra.0 +  8));
//                 let flags:   u32 = mm::read_phys(PhysAddr(sra.0 + 12));

//                 // Log the affinity record
//                 if (flags & FLAGS_ENABLED) != 0 {
//                         print!("APIC {:x} -> domain {:#x}\n", apic_id, domain);
//                     // assert!(apic_affinities.insert(apic_id, domain)
//                     //         .is_none(), "Duplicate APIC affinity domain");
//                 }
//             }
//             _ => {
//             }
//         }

//         // Go to the next ICS entry
//         sra = PhysAddr(sra.0 + len as u64);
//     }

// }
