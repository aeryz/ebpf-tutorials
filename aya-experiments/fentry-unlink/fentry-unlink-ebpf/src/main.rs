#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    cty::c_long,
    helpers::{bpf_probe_read, bpf_probe_read_kernel_str_bytes},
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::info;

use crate::vmlinux::filename;

mod vmlinux;

#[fentry(function = "do_unlinkat")]
pub fn fentry_unlink(ctx: FEntryContext) -> u32 {
    match try_fentry_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fentry_unlink(ctx: FEntryContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let f: *const filename = ctx.arg(1);
    let mut dest = [0; 192];
    let fname = unsafe {
        let f = bpf_probe_read(core::ptr::addr_of!((*f).name)).map_err(|x| x as u32)?;
        core::str::from_utf8_unchecked(
            bpf_probe_read_kernel_str_bytes(f as *const u8, dest.as_mut_slice())
                .map_err(|x| x as u32)?,
        )
    };
    info!(&ctx, "fentry: pid = {}, filename = {}", pid, fname);

    Ok(0)
}

#[fexit(function = "do_unlinkat")]
pub fn fexit_unlink(ctx: FExitContext) -> u32 {
    match try_fexit_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fexit_unlink(ctx: FExitContext) -> Result<u32, u32> {
    let ret = ctx.arg::<c_long>(2);
    info!(&ctx, "fexit: pid = {}, ret = {}", ctx.pid(), ret);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
