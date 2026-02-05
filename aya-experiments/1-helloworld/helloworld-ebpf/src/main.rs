#![no_std]
#![no_main]

use aya_ebpf::{EbpfContext, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[unsafe(no_mangle)]
static PID_FILTER: u32 = 0;

#[tracepoint]
pub fn helloworld(ctx: TracePointContext) -> u32 {
    match try_helloworld(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_helloworld(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let pid_filter = unsafe { core::ptr::read_volatile(&PID_FILTER) };
    if pid_filter != 0 && pid_filter != pid {
        return Ok(0);
    }
    info!(&ctx, "BPF triggered sys_enter_write from PID {}.", pid);
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
