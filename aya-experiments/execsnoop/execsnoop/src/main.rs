use aya::{
    maps::perf::{Events, PerfEventArray},
    programs::TracePoint,
    util::online_cpus,
};
use bytes::BytesMut;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pid: u32,
    ppid: i32,
    uid: u32,
    retval: i32,
    is_exit: bool,
    comm: [u8; 16],
}

unsafe impl aya::Pod for Event {}

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
        "/execsnoop"
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
    let program: &mut TracePoint = ebpf
        .program_mut("tracepoint_syscalls_sys_enter_execve")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    read_events(&mut ebpf).await?;
    println!("Exiting...");

    Ok(())
}

fn comm_to_string(comm: &[u8]) -> String {
    let end = comm.iter().position(|&c| c == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).to_string()
}

pub async fn read_events(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus().unwrap() {
        let buf = perf_array.open(cpu_id, None)?;
        let mut buf = tokio::io::unix::AsyncFd::with_interest(buf, tokio::io::Interest::READABLE)?;
        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let mut guard = buf.readable_mut().await.unwrap();
                let Events { read, lost: _ } =
                    guard.get_inner_mut().read_events(&mut buffers).unwrap();
                for buf in buffers.iter_mut().take(read) {
                    let ptr = buf.as_ptr() as *const Event;
                    let e = unsafe { *ptr };
                    println!(
                        "comm={} pid={} ppid={} uid={} is_exit={}",
                        comm_to_string(&e.comm),
                        e.pid,
                        e.ppid,
                        e.uid,
                        e.is_exit
                    );
                }
                guard.clear_ready();
            }
        });
    }

    signal::ctrl_c().await?;
    Ok(())
}
