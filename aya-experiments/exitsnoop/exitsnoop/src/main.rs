use std::os::fd::AsFd;

use aya::{maps::ring_buf::RingBuf, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pid: u32,
    ppid: u32,
    exit_code: u32,
    duraion_ns: u64,
    comm: [u8; 16],
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/exitsnoop"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut TracePoint = ebpf.program_mut("handle_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exit")?;

    read_events(&mut ebpf).await?;

    Ok(())
}

fn comm_to_string(comm: &[u8]) -> String {
    let end = comm.iter().position(|&c| c == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).to_string()
}

pub async fn read_events(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut ring_buf = RingBuf::try_from(bpf.take_map("RB").unwrap())?;
    let mut buf = tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    tokio::task::spawn(async move {
        loop {
            let mut guard = buf.readable_mut().await.unwrap();
            {
                let item = guard.get_inner_mut().next().unwrap();
                let ptr = item.as_ptr() as *const Event;
                let e = unsafe { *ptr };
                println!(
                    "pid={} ppid={} exit_code={}, duration_ns={}, comm={}",
                    e.pid,
                    e.ppid,
                    e.exit_code,
                    e.duraion_ns,
                    comm_to_string(&e.comm),
                );
            }
            guard.clear_ready();
        }
    });

    println!("Waiting for Ctrl+C");
    signal::ctrl_c().await?;
    println!("Exiting..");

    Ok(())
}
