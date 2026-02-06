#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, cty::c_long, helpers::bpf_probe_read_user_str_bytes, macros::uretprobe,
    programs::RetProbeContext,
};
use aya_log_ebpf::info;

#[uretprobe]
pub fn uprobe_bashreadline(ctx: RetProbeContext) -> u32 {
    match try_uprobe_bashreadline(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_bashreadline(ctx: RetProbeContext) -> Result<u32, u32> {
    let ret = ctx.ret::<*const u8>();
    if ret.is_null() {
        return Ok(0);
    }
    let c = ctx.command().map_err(|err| err as u32)?;
    let comm = unsafe { core::str::from_utf8_unchecked(c.as_slice()) };
    let pid = ctx.pid();

    let mut dest = [0; 192];
    let str_value = unsafe {
        core::str::from_utf8_unchecked(
            bpf_probe_read_user_str_bytes(ret, dest.as_mut_slice()).map_err(|x| x as u32)?,
        )
    };

    info!(&ctx, "PID {} ({}) read: {}", pid, comm, str_value);

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
