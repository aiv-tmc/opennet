//! Hardware fingerprinting for the three scored components (cpu, ram, gpu).
//!
//! A fingerprint identifies the physical component, not the running system:
//! rebooting the machine yields the identical fingerprint, while swapping the
//! component changes it. The score board compares the stored fingerprint with
//! the one collected at startup and resets only the components that differ.

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Stable identity of the scored hardware components.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Fingerprints {
    /// Hash of CPU model name plus logical core count.
    pub cpu: String,
    /// Hash of the total RAM size bucketed to 64 MiB (absorbs tiny
    /// reporting differences between boots).
    pub ram: String,
    /// Hash of the sorted set of GPU vendor:device identifiers.
    pub gpu: String,
}

/// Collect fingerprints of the currently installed hardware.
///
/// Every probe is best-effort and platform-independent in structure: on
/// non-Linux systems the individual readers fall back to sane placeholders
/// that still remain stable across reboots of the same machine.
pub fn collect() -> Fingerprints {
    Fingerprints {
        cpu: cpu_fingerprint(),
        ram: ram_fingerprint(),
        gpu: gpu_fingerprint(),
    }
}

/// Reduce an arbitrary identity string to a short stable hex token.
fn hash_id(raw: &str) -> String {
    let digest = blake3::hash(raw.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest.as_bytes()[..8] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Read the CPU model name and the logical core count from /proc/cpuinfo.
fn cpu_fingerprint() -> String {
    let mut model = String::from("unknown-cpu");
    let mut cores = 0u32;
    if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in text.lines() {
            if line.starts_with("model name") {
                if let Some((_, value)) = line.split_once(':') {
                    model = value.trim().to_string();
                }
            }
            // Count every "processor" stanza to obtain logical cores.
            if line.starts_with("processor") {
                cores += 1;
            }
        }
    }
    if cores == 0 {
        cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);
    }
    hash_id(&format!("{model}|{cores}"))
}

/// Read total memory from /proc/meminfo and bucket it to 64 MiB steps so
/// that BIOS/ kernel reservation jitter does not masquerade as a RAM swap.
fn ram_fingerprint() -> String {
    let mut mib = 0u64;
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                if let Some(kb) = rest.split_whitespace().next() {
                    if let Ok(kb) = kb.parse::<u64>() {
                        mib = kb / 1024;
                    }
                }
                break;
            }
        }
    }
    let bucket = mib / 64;
    hash_id(&format!("ram|{bucket}"))
}

/// Build the GPU identity from DRM device ids, with an nvidia-smi fallback
/// for systems where the DRM tree does not expose the pci ids.
fn gpu_fingerprint() -> String {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Only cardN entries represent physical adapters.
            if !name.starts_with("card") || name.contains('-') {
                continue;
            }
            let dev = entry.path().join("device");
            let vendor = std::fs::read_to_string(dev.join("vendor"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let device = std::fs::read_to_string(dev.join("device"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if !vendor.is_empty() && !device.is_empty() {
                ids.insert(format!("{vendor}:{device}"));
            }
        }
    }
    if ids.is_empty() {
        if let Ok(out) = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name,pci.bus_id", "--format=csv,noheader"])
            .output()
        {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    let line = line.trim();
                    if !line.is_empty() {
                        ids.insert(line.to_string());
                    }
                }
            }
        }
    }
    if ids.is_empty() {
        ids.insert("no-gpu".to_string());
    }
    hash_id(&ids.into_iter().collect::<Vec<_>>().join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_stable_across_calls() {
        // Collecting twice on the same machine must yield identical ids,
        // which is the property that distinguishes a reboot from a swap.
        let a = collect();
        let b = collect();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_id_is_deterministic_and_short() {
        let a = hash_id("intel|8");
        let b = hash_id("intel|8");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert_ne!(hash_id("intel|8"), hash_id("intel|16"));
    }
}
