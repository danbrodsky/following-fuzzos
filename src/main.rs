#![feature(asm, panic_info_message, bool_to_option)]
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[macro_use] mod print;
mod efi;
mod acpi;
mod mm;

use crate::efi::{EfiHandle,EfiStatus,EfiSystemTable};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    print!("PANIC!!!\n");

    if let Some(location) = info.location() {
        print!("{} {} {}\n",
               location.file(), location.line(), location.column());
    }
    if let Some(message) = info.message() {
        print!("{}\n", message);
    }
    loop {
        unsafe {asm!("hlt");}
    }
}

#[no_mangle]
extern fn efi_main(image_handle: EfiHandle,
system_table: *mut EfiSystemTable) -> EfiStatus {

    unsafe {
        efi::register_system_table(system_table);
    }

    efi::get_memory_map(image_handle);

    unsafe {
        acpi::init().unwrap();
    }

    panic!("the EFI is escaping!");
}
