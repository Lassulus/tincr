//! Regression: a UDP path that dies AFTER being confirmed must be
//! abandoned, not blackholed forever.
//!
//! `tcp_fallback.rs` covers the never-confirmed case (firewall up from
//! the start). This is the other half, and the one that bit production:
//! two nodes behind the SAME NAT confirm UDP over their LAN address,
//! then a relay hands each the other's NAT-reflexive address. The
//! gateway doesn't hairpin, so every probe from then on is dropped.
//!
//! Two defects made that terminal:
//!
//! 1. `udp_timed_out` measured from `udp_ping_sent`, which `try_udp`
//!    re-stamps on every keepalive *send*. With keepalive < timeout the
//!    deadline was unreachable, so `udp_confirmed` stayed pinned: no TCP
//!    fallback, no address re-exploration, no LAN probe. C arms the
//!    timer from the probe *reply*.
//! 2. With `udp_confirmed` pinned, PMTU discovery burned 20 unanswered
//!    probes and `try_fix_mtu` collapsed `maxmtu` to `minmtu == 0`.
//!    Nothing re-armed it, so every later cycle instantly "converged"
//!    to MTU 0 — observed as `Fixing MTU of <peer> to 0` every 3.4s.
//!
//! `UDPDiscoveryKeepaliveInterval` (3s) is deliberately shorter than
//! `UDPDiscoveryTimeout` (12s): that ordering is what made defect 1
//! unreachable-by-construction.

use std::process::{Command, Stdio};
use std::time::Duration;

use super::chaos::node_pmtu;
use super::common::linux::*;
use super::common::*;
use super::rig::*;

/// `udp_confirmed` bit in `dump nodes` status (`TunnelStatus::as_u32`).
const UDP_CONFIRMED: u32 = 0x80;
/// `validkey`.
const VALIDKEY: u32 = 0x02;
/// `reachable`.
const REACHABLE: u32 = 0x10;

#[test]
fn udp_confirmed_drops_when_path_dies() {
    let Some(netns) = enter_netns("udp_path_dies::udp_confirmed_drops_when_path_dies") else {
        return;
    };

    let tmp = tmp!("udpdies");
    let alice = tun_node(tmp.path(), "alice", 0xDA, "tinc0", "10.42.0.1/32");
    let bob = tun_node(tmp.path(), "bob", 0xDB, "tinc1", "10.42.0.2/32");
    // Same shape as tcp_fallback: no direct alice↔bob meta-conn, so
    // data for bob goes through relay=mid and the UDP path is the
    // hole-punched one — exactly the production topology.
    let extra = "AutoConnect = no\n\
                 UDPDiscoveryKeepaliveInterval = 3\n\
                 UDPDiscoveryInterval = 2\n\
                 UDPDiscoveryTimeout = 12\n";
    let alice = alice.with_conf(extra);
    let bob = bob.with_conf(extra);
    let mid = Node::new(tmp.path(), "mid", 0xDC).with_conf(extra);
    mid.write_config_multi(&[&alice, &bob], &[]);
    alice.write_config_multi(&[&mid, &bob], &["mid"]);
    bob.write_config_multi(&[&mid, &alice], &["mid"]);

    let log = "tincd=info,tincd::net=debug";
    let mut mid_child = mid.spawn_with_log(log);
    assert!(
        wait_for_file(&mid.socket),
        "mid setup; stderr:\n{}",
        drain_stderr(mid_child)
    );
    let mut bob_child = bob.spawn_with_log(log);
    if !wait_for_file(&bob.socket) {
        let _ = mid_child.kill();
        panic!("bob setup; stderr:\n{}", drain_stderr(bob_child));
    }
    let alice_child = alice.spawn_with_log(log);
    if !wait_for_file(&alice.socket) {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!("alice setup; stderr:\n{}", drain_stderr(alice_child));
    }

    assert!(wait_for_carrier("tinc0", Duration::from_secs(2)));
    assert!(wait_for_carrier("tinc1", Duration::from_secs(2)));
    netns.place_devices();

    let mut alice_ctl = alice.ctl();

    let ping_bob = || {
        Command::new("ping")
            .args(["-c", "3", "-W", "2", "10.42.0.2"])
            .output()
            .expect("spawn ping")
    };
    let kick = || {
        let _ = Command::new("ping")
            .args(["-c", "1", "-W", "1", "10.42.0.2"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };

    // ─── phase 1: UDP comes up and gets confirmed ────────────────
    let up = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(20), || {
            kick();
            let a = alice_ctl.dump(3);
            let st = node_status(&a, "bob")?;
            let (_, minmtu, _) = node_pmtu(&a, "bob")?;
            (st & (VALIDKEY | REACHABLE | UDP_CONFIRMED) == (VALIDKEY | REACHABLE | UDP_CONFIRMED)
                && minmtu > 0)
                .then_some(())
        });
    }));
    if up.is_err() {
        let _ = mid_child.kill();
        let _ = bob_child.kill();
        panic!(
            "alice never confirmed UDP to bob (precondition);\n\
             === alice ===\n{}\n=== mid ===\n{}\n=== bob ===\n{}",
            drain_stderr(alice_child),
            drain_stderr(mid_child),
            drain_stderr(bob_child)
        );
    }

    // ─── phase 2: the path dies under it ─────────────────────────
    // Same blunt instrument tcp_fallback uses: every inter-daemon UDP
    // datagram is dropped on input. Meta-conns are TCP and survive, so
    // bob stays reachable via mid — precisely the hairpin situation
    // (relay path fine, direct UDP a black hole).
    let ipt = Command::new("iptables")
        .args(["-I", "INPUT", "-p", "udp", "-j", "DROP"])
        .output()
        .expect("spawn iptables");
    if !ipt.status.success() {
        eprintln!(
            "SKIP udp_confirmed_drops_when_path_dies: iptables failed: {}",
            String::from_utf8_lossy(&ipt.stderr).trim()
        );
        // drain_stderr kills + reaps; don't leave zombies behind.
        let _ = drain_stderr(mid_child);
        let _ = drain_stderr(bob_child);
        let _ = drain_stderr(alice_child);
        drop(netns);
        return;
    }

    // UDPDiscoveryTimeout is 12s; give it 2x plus slack. The daemon
    // keeps sending 3s keepalives throughout — that is exactly what
    // used to hold the deadline open forever.
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_until(Duration::from_secs(40), || {
            kick();
            let a = alice_ctl.dump(3);
            let st = node_status(&a, "bob")?;
            (st & UDP_CONFIRMED == 0).then_some(())
        });
    }));

    // ─── phase 3: still usable over the relay ────────────────────
    let ping = if dropped.is_ok() {
        Some(ping_bob())
    } else {
        None
    };
    let after = alice_ctl.dump(3);

    drop(alice_ctl);
    let _ = mid_child.kill();
    let _ = bob_child.kill();
    let mid_stderr = drain_stderr(mid_child);
    let bob_stderr = drain_stderr(bob_child);
    let alice_stderr = drain_stderr(alice_child);

    assert!(
        dropped.is_ok(),
        "udp_confirmed never cleared after the path died — keepalive \
         sends must not hold the discovery deadline open.\n\
         === alice ===\n{alice_stderr}\n\
         === mid ===\n{mid_stderr}\n\
         === bob ===\n{bob_stderr}"
    );

    // Defect 2: `maxmtu` collapsed to 0 must never become absorbing.
    assert!(
        !alice_stderr.contains("Fixing MTU of bob to 0"),
        "PMTU discovery converged to MTU 0 — maxmtu was not re-armed.\n\
         === alice ===\n{alice_stderr}"
    );

    let ping = ping.expect("set whenever `dropped` is Ok");
    assert!(
        ping.status.success(),
        "bob must stay reachable via the mid relay after the direct UDP \
         path died.\nstdout: {}\nstderr: {}\nalice rows: {after:?}\n\
         === alice ===\n{alice_stderr}\n\
         === mid ===\n{mid_stderr}\n\
         === bob ===\n{bob_stderr}",
        String::from_utf8_lossy(&ping.stdout),
        String::from_utf8_lossy(&ping.stderr),
    );
    eprintln!("{}", String::from_utf8_lossy(&ping.stdout));

    drop(netns);
}
