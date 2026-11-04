use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::virtio::vsock::muxer::ProxyMap;
use crate::virtio::vsock::proxy::Proxy;
use crate::virtio::vsock::worker_control::{Owner, WorkerControl};
use crossbeam_channel::Sender;
use crossbeam_channel::{Receiver, select};

pub(crate) struct RetiredProxy {
    pub id: u64,
    released: Instant,
    proxy: Weak<Mutex<dyn Proxy>>,
}

pub(crate) fn defer_proxy(
    sender: &Sender<RetiredProxy>,
    id: u64,
    proxies: &ProxyMap,
) -> Result<(), ()> {
    let map = proxies.read().map_err(|_| ())?;
    let Some(proxy) = map.get(&id) else {
        return Ok(());
    };
    sender
        .send(RetiredProxy {
            id,
            released: Instant::now(),
            proxy: Arc::downgrade(proxy),
        })
        .map_err(|_| ())
}
const TIMEOUT: Duration = Duration::new(5, 0);

pub(crate) struct ReaperThread {
    receiver: Receiver<RetiredProxy>,
    proxy_map: ProxyMap,
    released_map: HashMap<u64, RetiredProxy>,
    control: Arc<WorkerControl>,
}

impl ReaperThread {
    pub(crate) fn new(
        receiver: Receiver<RetiredProxy>,
        proxy_map: ProxyMap,
        control: Arc<WorkerControl>,
    ) -> Self {
        Self {
            receiver,
            proxy_map,
            released_map: HashMap::new(),
            control,
        }
    }

    fn check_expiration(&mut self) -> Duration {
        let now = Instant::now();
        let Ok(mut proxies) = self.proxy_map.write() else {
            self.control.fail();
            return Duration::MAX;
        };
        self.released_map.retain(|id, retired| {
            let same_proxy = proxies
                .get(id)
                .is_some_and(|proxy| retired.proxy.ptr_eq(&Arc::downgrade(proxy)));
            if !same_proxy {
                return false;
            }
            if now.saturating_duration_since(retired.released) >= TIMEOUT {
                if proxies.remove(id).is_some() {
                    #[cfg(feature = "native-device-probe")]
                    self.control
                        .record(crate::virtio::vsock::worker_control::WorkerCounter::Reap);
                }
                false
            } else {
                true
            }
        });
        self.released_map
            .values()
            .map(|retired| TIMEOUT.saturating_sub(now.saturating_duration_since(retired.released)))
            .min()
            .unwrap_or(Duration::MAX)
    }

    fn work(&mut self) {
        while self.control.boundary(Owner::Reaper) {
            let epoch = self.control.epoch();
            let timeout = self.check_expiration();
            self.control.reconciled(Owner::Reaper, epoch);
            select! {
                recv(self.receiver) -> message => match message {
                    Ok(retired) => {
                        match self.released_map.entry(retired.id) {
                            std::collections::hash_map::Entry::Vacant(entry) => { entry.insert(retired); }
                            std::collections::hash_map::Entry::Occupied(mut entry) => {
                                if !entry.get().proxy.ptr_eq(&retired.proxy) || retired.released < entry.get().released {
                                    entry.insert(retired);
                                }
                            }
                        }
                    }
                    Err(_) => return,
                },
                recv(self.control.reaper_wake) -> _ => {},
                default(timeout) => {},
            }
        }
    }

    pub fn run(mut self) -> std::io::Result<thread::JoinHandle<()>> {
        thread::Builder::new()
            .name("vsock reaper".into())
            .spawn(move || self.work())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::HashMap;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::{Duration, Instant};

    use crossbeam_channel::unbounded;
    use nix::errno::Errno;
    use nix::sys::socket::{MsgFlags, recv};
    use vm_memory::GuestAddress;

    use crate::virtio::vsock::muxer::ProxyMap;
    use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
    use crate::virtio::vsock::proxy::Proxy;
    use crate::virtio::vsock::reaper::{ReaperThread, RetiredProxy, TIMEOUT, defer_proxy};
    use crate::virtio::vsock::unix_proxy::UnixProxy;
    use crate::virtio::vsock::worker_control::WorkerControl;
    use crate::virtio::{Queue, RuntimeGuestMemory};

    fn proxy(id: u64) -> (Arc<Mutex<dyn Proxy>>, UnixStream) {
        let (fd, peer) = UnixStream::pair().unwrap();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let proxy = UnixProxy::new_mux_reverse(
            id,
            3,
            id as u32,
            (id >> 32) as u32,
            fd.into(),
            memory,
            Arc::new(Mutex::new(
                crate::virtio::vsock::packet::PacketQueue::from_queue(Queue::new(256)),
            )),
            Arc::new(Mutex::new(MuxerRxQ::new())),
        );
        (Arc::new(Mutex::new(proxy)), peer)
    }

    #[test]
    fn provider_vsock_reaper_original_deadline_cannot_remove_reused_session_id() {
        let id = (1027u64 << 32) | (1 << 30);
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::new()));
        let (original, original_peer) = proxy(id);
        map.write().expect("proxy map").insert(id, original);
        let (sender, receiver) = unbounded();
        defer_proxy(&sender, id, &map).unwrap();
        let mut retired = receiver.recv().unwrap();
        retired.released = Instant::now().checked_sub(TIMEOUT).unwrap();
        let control = WorkerControl::new().unwrap();
        let mut reaper = ReaperThread::new(receiver, map.clone(), control);
        reaper.released_map.insert(id, retired);
        let (replacement, replacement_peer) = proxy(id);
        map.write().expect("proxy map").insert(id, replacement);
        assert_eq!(
            recv(
                original_peer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_DONTWAIT
            ),
            Ok(0)
        );
        assert_eq!(reaper.check_expiration(), Duration::MAX);
        assert_eq!(
            recv(
                replacement_peer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_DONTWAIT
            ),
            Err(Errno::EAGAIN)
        );
        defer_proxy(&sender, id, &map).unwrap();
        let mut current = reaper.receiver.recv().unwrap();
        current.released = Instant::now().checked_sub(TIMEOUT).unwrap();
        reaper.released_map.insert(id, current);
        assert_eq!(reaper.check_expiration(), Duration::MAX);
        assert!(map.read().expect("proxy map").is_empty());
        assert_eq!(
            recv(
                replacement_peer.as_raw_fd(),
                &mut [0u8; 1],
                MsgFlags::MSG_DONTWAIT
            ),
            Ok(0)
        );
    }

    #[test]
    fn provider_vsock_reaper_keeps_queued_release_time_across_park() {
        let id = (1027u64 << 32) | (1 << 30);
        let map: ProxyMap = Arc::new(RwLock::new(HashMap::new()));
        let (session, peer) = proxy(id);
        let retired = RetiredProxy {
            id,
            released: Instant::now().checked_sub(TIMEOUT).unwrap(),
            proxy: Arc::downgrade(&session),
        };
        map.write().expect("proxy map").insert(id, session);
        let (sender, receiver) = unbounded();
        sender
            .send(retired)
            .unwrap_or_else(|_| panic!("real reaper receiver closed"));
        let control = WorkerControl::new().unwrap();
        control.pause().unwrap();
        let worker = ReaperThread::new(receiver, map, control.clone())
            .run()
            .unwrap();
        assert_eq!(
            recv(peer.as_raw_fd(), &mut [0u8; 1], MsgFlags::MSG_DONTWAIT),
            Err(Errno::EAGAIN)
        );
        control.resume().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while recv(peer.as_raw_fd(), &mut [0u8; 1], MsgFlags::MSG_DONTWAIT) != Ok(0) {
            assert!(
                Instant::now() < deadline,
                "reaper restarted an already-expired deadline"
            );
            std::thread::yield_now();
        }
        control.stop();
        worker.join().unwrap();
    }
}
