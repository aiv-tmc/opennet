use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;

const FRAG_SIZE: usize = 250;
const HEADER_SIZE: usize = 8;

pub struct Fragmenter {
    pending: Arc<Mutex<HashMap<u32, Reassembly>>>,
}

struct Reassembly {
    received: Vec<Option<Bytes>>,
    _timestamp: tokio::time::Instant,
}

impl Fragmenter {
    pub fn new() -> Self {
        Self { pending: Arc::new(Mutex::new(HashMap::new())) }
    }
    
    pub fn fragment(&self, msg_id: u32, data: &Bytes) -> Vec<Bytes> {
        let total = (data.len() + FRAG_SIZE - 1) / FRAG_SIZE;
        let mut fragments = Vec::with_capacity(total);
        for seq in 0..total {
            let start = seq * FRAG_SIZE;
            let end = (start + FRAG_SIZE).min(data.len());
            let payload = &data[start..end];
            let mut header = BytesMut::with_capacity(HEADER_SIZE);
            header.extend_from_slice(&msg_id.to_be_bytes());
            header.extend_from_slice(&(total as u16).to_be_bytes());
            header.extend_from_slice(&(seq as u16).to_be_bytes());
            let mut frag = BytesMut::with_capacity(HEADER_SIZE + payload.len());
            frag.extend_from_slice(&header);
            frag.extend_from_slice(payload);
            fragments.push(frag.freeze());
        }
        fragments
    }
    
    pub async fn defragment(&self, header: &[u8; HEADER_SIZE], payload: &[u8]) -> Option<Bytes> {
        let msg_id = u32::from_be_bytes(header[0..4].try_into().unwrap());
        let total = u16::from_be_bytes(header[4..6].try_into().unwrap());
        let seq = u16::from_be_bytes(header[6..8].try_into().unwrap());
        
        let mut pending = self.pending.lock().await;
        let entry = pending.entry(msg_id).or_insert_with(|| Reassembly {
            received: vec![None; total as usize],
            _timestamp: tokio::time::Instant::now(),
        });
        
        entry.received[seq as usize] = Some(Bytes::copy_from_slice(payload));
        
        if entry.received.iter().all(|x| x.is_some()) {
            let mut complete = BytesMut::new();
            for frag in entry.received.drain(..) {
                complete.extend_from_slice(&frag.unwrap());
            }
            pending.remove(&msg_id);
            Some(complete.freeze())
        } else {
            None
        }
    }
}
