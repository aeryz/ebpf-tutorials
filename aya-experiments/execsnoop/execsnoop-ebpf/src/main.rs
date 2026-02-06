#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, TASK_COMM_LEN,
    cty::c_int,
    helpers::{bpf_probe_read, generated::bpf_get_current_task},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use crate::vmlinux::{task_struct, trace_event_raw_sys_enter};

mod vmlinux;

/// NOTE: unlike C where you define the key as well, the following map uses BPF_F_CURRENT_CPU.
#[map(name = "EVENTS")]
static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

struct Event {
    pid: u32,
    ppid: i32,
    uid: u32,
    retval: u32,
    is_exit: bool,
    comm: [u8; TASK_COMM_LEN],
}

#[tracepoint]
pub fn tracepoint_syscalls_sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_tracepoint_syscalls_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint_syscalls_sys_enter_execve(ctx: TracePointContext) -> Result<u32, u32> {
    let event = unsafe {
        ctx.read_at::<trace_event_raw_sys_enter>(0)
            .map_err(|e| e as u32)?
    };
    let uid = ctx.uid();
    let tgid = ctx.tgid();
    let task = unsafe { bpf_get_current_task() as (*const task_struct) };

    let ppid = unsafe {
        let parent =
            bpf_probe_read(core::ptr::addr_of!((*task).real_parent)).map_err(|e| e as u32)?;
        bpf_probe_read(core::ptr::addr_of!((*parent).tgid)).map_err(|e| e as u32)?
    };

    EVENTS.output(
        &ctx,
        &Event {
            pid: tgid,
            uid,
            ppid,
            retval: 0,
            is_exit: false,
            comm: ctx.command().map_err(|e| e as u32)?,
        },
        0,
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
