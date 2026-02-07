#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, TASK_COMM_LEN,
    helpers::{
        bpf_probe_read,
        generated::{bpf_get_current_task, bpf_ktime_get_ns},
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use crate::vmlinux::task_struct;

mod vmlinux;

struct Event {
    pid: u32,
    ppid: i32,
    exit_code: u32,
    duraion_ns: u64,
    comm: [u8; TASK_COMM_LEN],
}

#[map(name = "RB")]
static RB: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    match try_handle_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_handle_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = ctx.tgid();
    let tid = ctx.pid();

    if pid != tid {
        return Ok(0);
    }

    let task = unsafe { bpf_get_current_task() as *const task_struct };
    let start_time =
        unsafe { bpf_probe_read(core::ptr::addr_of!((*task).start_time)).map_err(|e| e as u32)? };

    let ppid = unsafe {
        let parent =
            bpf_probe_read(core::ptr::addr_of!((*task).real_parent)).map_err(|e| e as u32)?;
        bpf_probe_read(core::ptr::addr_of!((*parent).tgid)).map_err(|e| e as u32)?
    };

    let e = Event {
        pid,
        ppid,
        exit_code: unsafe {
            ((bpf_probe_read(core::ptr::addr_of!((*task).exit_code)).map_err(|e| e as u32)? as u32)
                >> 8)
                & 0xff
        },
        duraion_ns: unsafe { bpf_ktime_get_ns() } - start_time,
        comm: ctx.command().map_err(|e| e as u32)?,
    };

    let mut rb_entry = RB.reserve::<Event>(0).ok_or(1u32)?;
    rb_entry.write(e);
    rb_entry.submit(0);

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
