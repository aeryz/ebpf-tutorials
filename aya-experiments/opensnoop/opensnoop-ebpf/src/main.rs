#![no_std]
#![no_main]

use aya_ebpf::{EbpfContext, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

mod vmlinux;

#[unsafe(no_mangle)]
static PID_TARGET: u32 = 0;

#[tracepoint]
pub fn opensnoop(ctx: TracePointContext) -> u32 {
    match try_opensnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_opensnoop(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let pid_target = unsafe { core::ptr::read_volatile(&PID_TARGET) };
    if (pid_target != 0 && pid != pid_target) {
        return Ok(0);
    }
    info!(&ctx, "Process ID: {} enter sys openat.", pid);
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
