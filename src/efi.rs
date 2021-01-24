use core::sync::atomic::{AtomicPtr, Ordering};

static EFI_SYSTEM_TABLE: AtomicPtr<EfiSystemTable> =
    AtomicPtr::new(core::ptr::null_mut());

pub unsafe fn register_system_table(system_table: *mut EfiSystemTable) {
    EFI_SYSTEM_TABLE.compare_and_swap(core::ptr::null_mut(), system_table,
                                      Ordering::SeqCst);
}


pub fn output_string(string: &str) {

    let st = EFI_SYSTEM_TABLE.load(Ordering::SeqCst);

    if st.is_null() { return; }

    let out = unsafe {
        (*st).console_out
    };


    // UEFI uses USC-2, we convert to UTF-16 for reading
    // each tmp buffer holds 31 chars and a null terminator
    let mut tmp = [0u16; 32];
    let mut in_use = 0;

    for chr in string.encode_utf16() {
        // converts newlines to CRLF
        if chr == b'\n' as u16 {
            tmp[in_use] = b'\r' as u16;
            in_use += 1;
        }

        tmp[in_use] = chr;
        in_use += 1;

        if in_use == (tmp.len() - 2) {
            tmp[in_use] = 0;

            unsafe {
                ((*out).output_string)(out, tmp.as_ptr());
            }

            in_use = 0;
        }
    }

    if in_use > 0 {
        tmp[in_use] = 0;

        unsafe {
            ((*out).output_string)(out, tmp.as_ptr());
        }
    }
}

/// Get base of ACPI table
pub fn get_acpi_table() -> Option<usize> {
    /// ACPI 2.0 table
    const EFI_ACPI_TABLE_GUID: EfiGuid =
        EfiGuid(0x8868e871, 0xe4f1, 0x11d3, [0xbc, 0x22, 0x0, 0x80, 0xc7, 0x3c, 0x88, 0x81]);

    /// ACPI 1.0 table
    const ACPI_TABLE_GUID: EfiGuid =
        EfiGuid(0xeb9d2d30, 0x2d88, 0x11d3, [0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d]);

    // Get the system table
    let st = EFI_SYSTEM_TABLE.load(Ordering::SeqCst);

    // Can't do anything if its null
    if st.is_null() { return None }

    // convert ref to rust ref
    // let st = unsafe { &*st };

    let tables = unsafe {
        core::slice::from_raw_parts(
            (*st).tables,
            (*st).number_of_tables)
    };

    // Get ACPI 2 table ptr, 1.0 if not found
    let acpi = tables.iter().find_map(|EfiConfigurationTable { guid, table }| {
        (guid == &EFI_ACPI_TABLE_GUID).then_some(*table)
    }).or_else(|| {
        tables.iter().find_map(|EfiConfigurationTable { guid, table }| {
        (guid == &ACPI_TABLE_GUID).then_some(*table)
        })
    });

    print!("ACPI at {:#x?} {:#x}\n", acpi, unsafe {
        core::ptr::read_unaligned(acpi.unwrap() as *const u64)
    });

    acpi

}


pub fn get_memory_map(_image_handle: EfiHandle) {
    let st = EFI_SYSTEM_TABLE.load(Ordering::SeqCst);

    if st.is_null() {return;}

    let mut memory_map = [0u8; 6 * 1024];
    let mut free_memory = 0u64;
    unsafe {
        let mut size = core::mem::size_of_val(&memory_map);
        let mut key = 0;
        let mut mdesc_size = 0;
        let mut mdesc_version = 0;

        let ret = ((*(*st).boot_services).get_memory_map)(
            &mut size,
            memory_map.as_mut_ptr(),
            &mut key,
            &mut mdesc_size,
            &mut mdesc_version);

        assert!(ret.0 == 0, "{:x?} {:016x}", ret, size);

        for off in (0..size).step_by(mdesc_size) {
            let entry = core::ptr::read_unaligned(
                memory_map[off..].as_ptr() as *const EfiMemoryDescriptor
            );
            let typ: EfiMemoryType = entry.typ.into();

            if typ.avail_post_exit_boot_services() {
                free_memory += entry.number_of_pages * 4096;
            }


        //     print!("{:016x} {:016x} {:?}\n",
        //            entry.physical_start,
        //            entry.number_of_pages * 4096,
        //            typ);
        }

        // print!("{:016x} key\n", key);
        // exit boot services
        // let ret = ((*(*st).boot_services).exit_boot_services)(
        //     image_handle, key);
        // assert!(ret.0 == 0, "Failed to exit boot services {:x?}", ret);


        // Clear the EFI system table
        // EFI_SYSTEM_TABLE.store(core::ptr::null_mut(), Ordering::SeqCst);
    }

    // print!("Total bytes free {}\n", free_memory);
}


#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EfiHandle(usize);

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EfiStatus(pub usize);

#[repr(C)]
struct EfiInputKey {
    scan_code: u16,
    unicode_char: u16,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
enum EfiMemoryType {
    ReservedMemoryType,
    LoaderCode,
    LoaderData,
    BootServicesCode,
    BootServicesData,
    RuntimeServicesCode,
    RuntimeServicesData,
    ConventionalMemory,
    UnusableMemory,
    ACPIReclaimMemory,
    ACPIMemoryNVS,
    MemoryMappedIO,
    MemoryMappedIOPortSpace,
    PalCode,
    PersistentMemory,
    Invalid,
}

impl EfiMemoryType {
    fn avail_post_exit_boot_services(&self) -> bool {
        match self {
            EfiMemoryType::BootServicesCode |
            EfiMemoryType::BootServicesData |
            EfiMemoryType::ConventionalMemory |
            EfiMemoryType::PersistentMemory => true,
            _ => false
        }
    }
}

impl From<u32> for EfiMemoryType {
    fn from(val: u32) -> Self {
        match val {
             0  => EfiMemoryType::ReservedMemoryType,
             1  => EfiMemoryType::LoaderCode,
             2  => EfiMemoryType::LoaderData,
             3  => EfiMemoryType::BootServicesCode,
             4  => EfiMemoryType::BootServicesData,
             5  => EfiMemoryType::RuntimeServicesCode,
             6  => EfiMemoryType::RuntimeServicesData,
             7  => EfiMemoryType::ConventionalMemory,
             8  => EfiMemoryType::UnusableMemory,
             9  => EfiMemoryType::ACPIReclaimMemory,
            10  => EfiMemoryType::ACPIMemoryNVS,
            11  => EfiMemoryType::MemoryMappedIO,
            12  => EfiMemoryType::MemoryMappedIOPortSpace,
            13  => EfiMemoryType::PalCode,
            14  => EfiMemoryType::PersistentMemory,
            _   => EfiMemoryType::Invalid,
        }
    }
}

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[derive(Clone, Copy, Default, Debug)]
#[repr(C)]
struct EfiMemoryDescriptor {
    // type of memory region
    typ: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

#[repr(C)]
struct EfiBootServices {
    header: EfiTableHeader,
    _raise_tpl: usize,
    _restore_tpl: usize,
    _allocate_pages: usize,
    _free_pages: usize,

    get_memory_map: unsafe fn(memory_map_size: &mut usize,
                              memory_map: *mut u8,
                              map_key: &mut usize,
                              descriptor_size: &mut usize,
                              descriptor_version: &mut u32) -> EfiStatus,
    _allocate_pool: usize,
    _free_pool: usize,
    _create_event: usize,
    _set_timer: usize,
    _wait_for_event: usize,
    _signal_event: usize,
    _close_event: usize,
    _check_event: usize,
    _install_protocol_interface: usize,
    _reinstall_protocol_interface: usize,
    _uninstall_protocol_interface: usize,
    _handle_protocol: usize,
    _reserved: usize,
    _register_protocol_notify: usize,
    _locate_handle: usize,
    _locate_device_path: usize,
    _install_configuration_table: usize,
    _load_image: usize,
    _start_image: usize,
    _exit: usize,
    _unload_image: usize,
    exit_boot_services: unsafe fn(image_handle: EfiHandle,
                                  map_key: usize) -> EfiStatus,
}

#[repr(C)]
struct EfiSimpleTextInputProtocol {
    reset: unsafe fn(this: *const EfiSimpleTextInputProtocol,
                     extended_verification: bool) -> EfiStatus,
    read_keystroke: unsafe fn(this: *const EfiSimpleTextInputProtocol,
                              key: *mut EfiInputKey) -> EfiStatus,
    _wait_for_key: usize,
}


#[repr(C)]
struct EfiSimpleTextOutputProtocol {
    reset: unsafe fn(this: *const EfiSimpleTextOutputProtocol,
                     extended_verification: bool) -> EfiStatus,
    output_string: unsafe fn(this: *const EfiSimpleTextOutputProtocol,
                              string: *const u16) -> EfiStatus,
    test_string: unsafe fn(this: *const EfiSimpleTextOutputProtocol,
                              string: *const u16) -> EfiStatus,
    _query_mode: usize,
    _set_mode: usize,
    _set_attribute: usize,
    _clear_screen: usize,
    _set_cursor_position: usize,
    _enable_cursor: usize,
    _mode: usize,
}

#[repr(C)]
pub struct EfiSystemTable {
    header: EfiTableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: EfiHandle,
    console_in: *const EfiSimpleTextInputProtocol,
    console_out_handle: EfiHandle,
    console_out: *const EfiSimpleTextOutputProtocol,
    console_err_handle: EfiHandle,
    console_err: *const EfiSimpleTextOutputProtocol,
    _runtime_services: usize,
    boot_services: *const EfiBootServices,
    number_of_tables: usize,
    tables: *const EfiConfigurationTable,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct EfiConfigurationTable {
    guid: EfiGuid,
    table: usize,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct EfiGuid (u32, u16, u16, [u8; 8]);
