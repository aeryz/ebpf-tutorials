#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext, TASK_COMM_LEN,
    bindings::BPF_ANY,
    cty::{c_int, c_uint},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use crate::vmlinux::{trace_event_raw_sys_enter, trace_event_raw_sys_exit};

mod vmlinux;

const MAX_ENTRIES: u32 = 10240;

#[repr(C)]
struct Event {
    pid: c_uint,
    tpid: c_uint,
    sig: c_int,
    ret: c_int,
    comm: [u8; TASK_COMM_LEN],
}

#[map(name = "VALUES")]
static VALUES: HashMap<u32, Event> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[tracepoint]
pub fn kill_entry(ctx: TracePointContext) -> u32 {
    match try_kill_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kill_entry(ctx: TracePointContext) -> Result<u32, u32> {
    let event = unsafe {
        ctx.read_at::<trace_event_raw_sys_enter>(0)
            .map_err(|e| e as u32)?
    };
    let tpid = event.args[0] as c_uint;
    let sig = event.args[1] as c_int;

    VALUES
        .insert(
            &ctx.pid(),
            &Event {
                pid: ctx.tgid(),
                tpid,
                sig,
                ret: 0,
                comm: ctx.command().map_err(|e| e as u32)?,
            },
            BPF_ANY.into(),
        )
        .map_err(|e| e as u32)?;
    Ok(0)
}

#[tracepoint]
pub fn kill_exit(ctx: TracePointContext) -> u32 {
    match try_kill_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kill_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let event = unsafe {
        ctx.read_at::<trace_event_raw_sys_exit>(0)
            .map_err(|e| e as u32)?
    };
    let ret = event.ret as c_int;

    let pid = ctx.tgid();
    let Some(event) = VALUES.get_ptr_mut(&pid) else {
        return Ok(0);
    };

    unsafe {
        (*event).ret = ret;
        info!(
            &ctx,
            "PID {} ({}) sent signal {}",
            (*event).pid,
            str::from_utf8_unchecked((*event).comm.as_slice()),
            (*event).sig
        );
        info!(&ctx, "to PID {}, ret = {}", (*event).tpid, ret);
    }
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
