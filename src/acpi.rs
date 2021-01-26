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


/// result types which wraps ACPI error
type Result<T> = core::result::Result<T, Error>;


/// Different types of ACPI table, for error info
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TableType {
    Rsdp,
    RsdpExtended,
    Xsdt,
    Unknown([u8; 4]),
}


impl From<[u8; 4]> for TableType {
    fn from(val: [u8; 4]) -> Self {
        match &val {
            b"XSDT" => Self::Xsdt,
            _       => Self::Unknown(val),
        }
    }
}



/// Errors from ACPI table parsing
#[derive(Debug)]
pub enum Error {
    /// ACPI table not reported by UEFI
    RsdpNotFound,

    /// some ACPI table had an invalid checksum
    ChecksumMismatch(TableType),

    /// An ACPI table did not match correct signature
    SignatureMismatch(TableType),

    /// Extended RSDP was attempted to be accessed, but ACPI 2.0 not supported
    RevisionTooOld,

    /// ACPI did not match the expected length
    LengthMismatch(TableType),

    /// XSDT table size was not evenly divisible by array element size
    XsdtBadEntries,

    /// An integer overflow occurred
    IntegerOverflow,

}


/// In-memory representation of an RSDP ACPI structure
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct Rsdp {
    // "RSD PTR "
    signature:  [u8; 8],
    checksum:   u8,
    oem_id:     [u8; 6],
    revision:   u8,
    rsdt_addr:  u32,
}

/// Root System Description Pointer for getting the RSDT/XSDT
impl Rsdp {
    /// Load an RSDP struct from `addr`
    unsafe fn from_addr(addr: PhysAddr) -> Result<Self> {
        // Validate the checksum
        checksum(addr, size_of::<Self>(), TableType::Rsdp)?;

        // read base RSDP struct
        let rsdp = mm::read_phys::<Self>(addr);

        // check signature
        if &rsdp.signature != b"RSD PTR " {
            return Err(Error::SignatureMismatch(TableType::Rsdp));
        }

        // looks good, return rsdp
        Ok(rsdp)
    }
}

/// In-memory representation of an Extended RSDP ACPI structure
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct RsdpExtended {
    base:              Rsdp,
    length:            u32,
    xsdt_addr:         u64,
    extended_checksum: u8,
    reserved:          [u8; 3],
}

impl RsdpExtended {
    /// Load an Extended RSDP struct from `addr`
    unsafe fn from_addr(addr: PhysAddr) -> Result<Self> {
        // read RSDP for ACPI 1.0 structure
        // this extended RSDP requires ACPI 2.0
        let rsdp = Rsdp::from_addr(addr)?;

        if rsdp.revision < 2 {
            return Err(Error::RevisionTooOld);
        }

        print!("{:#x?}", rsdp);
        checksum(addr, size_of::<Self>(), TableType::RsdpExtended)?;


        let rsdp = mm::read_phys::<Self>(addr);

        // check the size
        if rsdp.length as usize != size_of::<Self>() {
            return Err(Error::LengthMismatch(TableType::RsdpExtended));
        }

        // looks good, return rsdp
        Ok(rsdp)

    }
}



/// Get a fixed size table from
// unsafe fn get_fixed_table<T>(addr: PhysAddr, typ: TableType) -> Result<T>{
//     let table = mm::read_phys::<T>(addr);
//     checksum(addr, size_of::<T>(), typ)?;

//     Ok(table)

// }

/// Compute ACPI checksum on physical memory
unsafe fn checksum(addr: PhysAddr, size: usize, typ: TableType) -> Result<()> {

    // Compute checksum
    let chk = (0..size as u64).try_fold(0u8, |acc, offset| {
        Ok(acc.wrapping_add(
            mm::read_phys::<u8>(PhysAddr(addr.0.checked_add(offset)
            .ok_or(Error::IntegerOverflow)?))))
    })?;

    // Validate checksum
    if chk == 0 {
        Ok(())
    } else {
        return Err(Error::ChecksumMismatch(typ));
    }
}

/// In-memory representation of an ACPI table header
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct Table {
    /// ASCI string representation of table identifier
    signature:        [u8; 4],
    /// length of table and header in bytes
    length:           u32,
    /// version of table used
    revision:         u8,
    /// entire table must add to 0 to be valid
    checksum:         u8,
    /// identifies the OEM
    oemid:            [u8; 6],
    /// identifier for the OEM's particular data table
    oem_table_id:     u64,
    /// OEM revision number
    oem_revision:     u32,
    /// vendor identifier for creator of this table
    creator_id:       u32,
    /// vendor revision number
    creator_revision: u32,
}

impl Table {
    /// Gets the requested table if available at `addr`, or returns None
    /// Return header, type of table, address of contents, content length
    unsafe fn from_addr(addr: PhysAddr)
                        -> Result<(Self, TableType, PhysAddr, usize)> {

        let table = mm::read_phys::<Self>(addr);

        let typ = TableType::from(table.signature);

        // Validate the checksum
        checksum(addr, table.length as usize, typ)?;

        let header_size = size_of::<Self>();
        let payload_size = (table.length as usize).checked_sub(header_size)
            .ok_or(Error::LengthMismatch(typ))?;
        let payload_addr = PhysAddr(addr.0 + header_size as u64);
        let payload_addr = PhysAddr(addr.0.checked_add(header_size as u64)
            .ok_or(Error::IntegerOverflow)?);


        Ok((table, typ, payload_addr, payload_size))
    }
}

/// Parse a standard ACPI table header. This will parse out the header,
/// validate the checksum and length, and return a physical address and size
/// of the payload following the header.
// unsafe fn parse_header(addr: PhysAddr) -> (Header, PhysAddr, usize) {
//     // Read the header
//     let head = mm::read_phys::<Header>(addr);

//     // Get the number of bytes for the table
//     let payload_len = head.length
//         .checked_sub(size_of::<Header>() as u32)
//         .expect("Integer underflow on table length");

//     // Check the checksum for the table
//     let sum = (addr.0..addr.0 + head.length as u64)
//         .fold(0u8, |acc, paddr| {
//             acc.wrapping_add(mm::read_phys(PhysAddr(paddr as u64)))
//         });
//     assert!(sum == 0, "Table checksum invalid {:?}",
//             core::str::from_utf8(&head.signature));

//     // Return the parsed header
//     (head, PhysAddr(addr.0 + size_of::<Header>() as u64), payload_len as usize)
// }

/// Initialize the ACPI subsystem
pub unsafe fn init() -> Result<()> {

    let rsdp_addr = efi::get_acpi_table()
        .ok_or(Error::RsdpNotFound)?;

    let rsdp = RsdpExtended::from_addr(PhysAddr(rsdp_addr as u64))?;

    let (_, typ, xsdt, len) = Table::from_addr(PhysAddr(rsdp.xsdt_addr))?;
    if typ != TableType::Xsdt {
        return Err(Error::SignatureMismatch(TableType::Xsdt));
    }

    // Make sure XSDT size is modulo a 64-bit addr size
    if len % size_of::<u64>() != 0 {
        return Err(Error::XsdtBadEntries);
    }

    // get num entries in XSDT
    let entries = len / size_of::<u64>();

    for idx in 0..entries {
        // read the table ptr from XSDT
        let entry_addr = idx.checked_mul(size_of::<u64>()).and_then(|x| {
            x.checked_add(xsdt.0 as usize)
        }).ok_or(Error::IntegerOverflow)?;

        // Get table addr by reading XSDT entry
        // Observed in OVMF
        let table_addr = mm::read_phys_unaligned::<u64>(
            PhysAddr(entry_addr as u64));


        let (_, typ, data, len) = Table::from_addr(PhysAddr(table_addr))?;

        print!("{:?} {}\n", typ, len);
    }





    print!("{:#x?}\n", xsdt);


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
