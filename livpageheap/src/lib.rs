use std::ops::{BitAnd, Sub};

use libc::{
    mprotect, munmap, sysconf, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, _SC_PAGE_SIZE,
};


static mut PAGE_SIZE: Option<usize> = Option::<usize>::None;

#[ctor::ctor]
fn init() {
    let ps = unsafe { sysconf(_SC_PAGE_SIZE) as usize };

    unsafe {
        PAGE_SIZE = ps.into();
    };

    #[cfg(debug_prints)]
    libc_eprintln!("[PageHeap] PageHeapInit with PageSize={ps:4x}");
}

#[no_mangle]
pub unsafe extern "C" fn safe_malloc(size: usize) -> *mut core::ffi::c_void {
    assert!(size as isize >= 0);
    #[cfg(debug_prints)]
    libc_eprintln!("[PageHeap] Allocation request {size} bytes");
    // SAFETY:
    // PAGE_SIZE is set in the library constructor.
    // It should always be presend and a power of 2.
    let ps = unsafe { PAGE_SIZE.expect("PAGE_SIZE to be present") };

    // Create a page aligned allocation that would fit
    // the desired size
    let alloc_size = size + 1 + (ps - 1).bitand(!size);

    #[cfg(debug_prints)]
    println!("Allocating size {alloc_size:16x}");

    let alloc_addr = unsafe {
        // Allocate an extra guard page and a size page
        libc::mmap(
            core::ptr::null_mut(),
            alloc_size
                .checked_add(ps * 2)
                .expect("alloc_size not to overflow"),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    assert!(!alloc_addr.is_null(), "MMAP page allocation failed");

    let usable_mem = unsafe { alloc_addr.add(ps) };

    // Write the allocation size so it can be used later to
    // properly free the pages
    unsafe {
        (alloc_addr as *mut usize).write(alloc_size);
    }

    assert!(
        unsafe { mprotect(alloc_addr, ps, PROT_READ) } == 0,
        "Failed to set guard pre-page protection"
    );

    assert!(
        unsafe { mprotect(usable_mem.add(alloc_size), ps, PROT_READ) } == 0,
        "Failed to set guard post-page protection"
    );

    unsafe { usable_mem.add(ps - size % ps) }
}

#[no_mangle]
pub unsafe extern "C" fn safe_free(ptr: *mut core::ffi::c_void) {
    if ptr.is_null() {
        return;
    }
    // SAFETY:
    // PAGE_SIZE is set in the library constructor.
    // It should always be presend and a power of 2.
    let ps = unsafe { PAGE_SIZE.expect("PAGE_SIZE to be present") };

    let base = (ptr as usize).bitand(!(ps - 1)).sub(ps) as *mut usize;

    let alloc_size = unsafe { base.read() };

    #[cfg(debug_prints)]
    println!("Freeing size {alloc_size:16x}");

    assert!(
        unsafe { munmap(base as *mut core::ffi::c_void, alloc_size + 2 * ps) } == 0,
        "Failed to free memory"
    );
}
