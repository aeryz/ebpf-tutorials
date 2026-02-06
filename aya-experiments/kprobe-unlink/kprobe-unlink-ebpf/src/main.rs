#![no_std]
#![no_main]

mod vmlinux;

use core::slice;

use aya_ebpf::{
    EbpfContext,
    bindings::task_struct,
    helpers::{bpf_probe_read, bpf_probe_read_kernel_str_bytes},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;

use crate::vmlinux::filename;

#[kprobe]
pub fn kprobe_unlink(ctx: ProbeContext) -> u32 {
    match try_kprobe_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kretprobe]
pub fn kretprobe_unlink(ctx: RetProbeContext) -> u32 {
    match try_kretprobe_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kprobe_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let f: *const filename = ctx.arg(1).ok_or(1u32)?;
    let mut dest = [0; 192];
    let fname = unsafe {
        let f = bpf_probe_read(core::ptr::addr_of!((*f).name)).map_err(|x| x as u32)?;
        core::str::from_utf8_unchecked(
            bpf_probe_read_kernel_str_bytes(f as *const u8, dest.as_mut_slice())
                .map_err(|x| x as u32)?,
        )
    };
    info!(&ctx, "KPROBE ENTRY: pid = {}, filename = {}", pid, fname);

    Ok(0)
}

fn try_kretprobe_unlink(ctx: RetProbeContext) -> Result<u32, u32> {
    info!(
        &ctx,
        "KPROBE EXIT: pid = {}, ret = {}",
        ctx.pid(),
        ctx.ret::<i64>()
    );
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
