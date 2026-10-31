// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project
//! Control of the physical data device `rmnet_ipa0`: the endpoint it reports, the data format of the IPA
//! pipes and the registration of every mux ID. Byte layouts of `struct rmnet_ioctl_extended_s` and
//! `struct rmnet_ioctl_extended_s_v2`, and the numbers, come from the UAPI header `linux/msm_rmnet.h`
//! (GPL-2.0 with the syscall note, facts only) and the handlers in the `dataipa` driver of the 6.18 tree.
//! The ioctls are `SIOCDEVPRIVATE + 13` with the structure behind `ifr_data`, and `SIOCDEVPRIVATE + 14` for the
//! pipes, whose structure holds the address of an array of parameters, one for each endpoint.
//!
//! Driver facts that shape the engine:
//! - the ingress format sets up the downlink pipes, the QMAP header and the default WAN routing tables.
//!   Without it the AP gets no downlink.
//! - the egress format sets up the uplink pipe.
//! - a pipe that is up already is reported as such in the status the driver writes back to the array, and
//!   is not set up again. A pipe that failed is reported as failed, also when the ioctl itself returns 0.
//! - add mux channel registers `(mux ID, link name)` once. The driver keeps 15 such entries
//!   (`MAX_NUM_OF_MUX_CHANNEL`) and answers 0 for a mux ID it already knows. Only the first 15 distinct mux
//!   IDs can be used.
//! - the driver unregisters `rmnet_ipa0` when the modem shuts down and registers a new one after power-up,
//!   so all of this has to be redone after a modem restart.

use crate::ops::{EgressPipe, Endpoint, IngressPipe, NetError, PipeStatus};
use crate::rtnl::BuildError;

/// `SIOCDEVPRIVATE + 13`.
pub const RMNET_IOCTL_EXTENDED: u32 = 0x0000_89FD;
/// `SIOCDEVPRIVATE + 14`.
pub const RMNET_IOCTL_EXTENDED_V2: u32 = 0x0000_89FE;
pub const EXT_GET_EPID: u32 = 0x0003;
pub const EXT_ADD_MUX_CHANNEL: u32 = 0x0005;
pub const EXT_GET_EP_PAIR: u32 = 0x0010;
/// The `extended_v2_ioctl_type` of the two formats.
pub const V2_EGRESS: u32 = 0;
pub const V2_INGRESS: u32 = 1;

/// Distinct mux IDs the driver accepts.
pub const MAX_MUX_CHANNELS: usize = 15;

/// Size of `struct rmnet_ioctl_extended_s` (a `u32` and a 20-byte union).
pub const EXT_LEN: usize = 24;
/// Size of `struct rmnet_ioctl_extended_s_v2`, `struct egress_format_v2` and `struct ingress_format_v2`.
pub const V2_LEN: usize = 16;
/// Size of `struct rmnet_egress_param` and `struct rmnet_ingress_param`.
pub const EGRESS_PARAM_LEN: usize = 32;
pub const INGRESS_PARAM_LEN: usize = 40;
const IFNAMSIZ: usize = 16;

/// Data format of the two pipes, as stock nicmd sends it on the FP6 (read from a stock trace). The
/// egress side has the default pipe and the low latency control pipe, the ingress side the coalescing, default
/// and low latency control pipes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaFormat {
    pub egress: Vec<EgressPipe>,
    pub ingress: Vec<IngressPipe>,
}

impl Default for IpaFormat {
    fn default() -> Self {
        let data_in = |ep_type| IngressPipe {
            ep_type,
            cs_offload: true,
            buff_size: 16384,
            agg_byte_limit: 64844,
            agg_time_limit: 500,
            agg_pkt_limit: 63,
            int_modt: 16,
            int_modc: 20,
        };
        IpaFormat {
            egress: vec![
                EgressPipe {
                    ep_type: EgressPipe::DEFAULT,
                    cs_offload: true,
                    aggregation: true,
                    ulso: true,
                    ipid_min_max_idx: 0,
                    int_modt: 16,
                    int_modc: 20,
                },
                EgressPipe {
                    ep_type: EgressPipe::LOW_LAT_CTRL,
                    cs_offload: false,
                    aggregation: false,
                    ulso: false,
                    ipid_min_max_idx: 0,
                    int_modt: 16,
                    int_modc: 1,
                },
            ],
            ingress: vec![
                data_in(IngressPipe::COALESCING),
                data_in(IngressPipe::DEFAULT),
                IngressPipe {
                    ep_type: IngressPipe::LOW_LAT_CTRL,
                    cs_offload: false,
                    buff_size: 4096,
                    agg_byte_limit: 0,
                    agg_time_limit: 0,
                    agg_pkt_limit: 0,
                    int_modt: 16,
                    int_modc: 1,
                },
            ],
        }
    }
}

fn put(buf: &mut [u8], at: usize, v: u32) {
    if let Some(dst) = buf.get_mut(at..at.saturating_add(4)) {
        dst.copy_from_slice(&v.to_ne_bytes());
    }
}

fn put64(buf: &mut [u8], at: usize, v: u64) {
    if let Some(dst) = buf.get_mut(at..at.saturating_add(8)) {
        dst.copy_from_slice(&v.to_ne_bytes());
    }
}

fn get(buf: &[u8], at: usize) -> u32 {
    buf.get(at..at.saturating_add(4))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_ne_bytes)
}

fn ext(code: u32) -> [u8; EXT_LEN] {
    let mut b = [0u8; EXT_LEN];
    put(&mut b, 0, code);
    b
}

/// `RMNET_IOCTL_GET_EPID`: the endpoint (interface) number comes back in `u.data`.
pub fn get_epid() -> [u8; EXT_LEN] {
    ext(EXT_GET_EPID)
}

/// `RMNET_IOCTL_GET_EP_PAIR`: the consumer and the producer pipe numbers come back in `u.ipa_ep_pair`.
pub fn get_ep_pair() -> [u8; EXT_LEN] {
    ext(EXT_GET_EP_PAIR)
}

/// The answers to `get_epid` and `get_ep_pair`.
pub fn endpoint_of(epid: &[u8; EXT_LEN], pair: &[u8; EXT_LEN]) -> Endpoint {
    Endpoint {
        epid: get(epid, 4),
        consumer: get(pair, 4),
        producer: get(pair, 8),
    }
}

/// `RMNET_IOCTL_ADD_MUX_CHANNEL`: `u.rmnet_mux_val` holds the mux ID and the
/// link name.
pub fn add_mux_channel(mux_id: u32, link: &str) -> Result<[u8; EXT_LEN], BuildError> {
    let name = link.as_bytes();
    if name.is_empty() || name.len() >= IFNAMSIZ || name.contains(&0) {
        return Err(BuildError::BadName);
    }
    let mut b = ext(EXT_ADD_MUX_CHANNEL);
    put(&mut b, 4, mux_id);
    if let Some(dst) = b.get_mut(8..8usize.saturating_add(name.len())) {
        dst.copy_from_slice(name);
    }
    Ok(b)
}

/// One `struct rmnet_egress_param`. The status is written by the driver.
pub fn egress_param(p: &EgressPipe) -> [u8; EGRESS_PARAM_LEN] {
    let mut b = [0u8; EGRESS_PARAM_LEN];
    put(&mut b, 0, p.ep_type);
    put(&mut b, 8, u32::from(p.cs_offload));
    put(&mut b, 12, u32::from(p.aggregation));
    put(&mut b, 16, u32::from(p.ulso));
    put(&mut b, 20, p.ipid_min_max_idx);
    put(&mut b, 24, p.int_modt);
    put(&mut b, 28, p.int_modc);
    b
}

/// One `struct rmnet_ingress_param`. The status is written by the driver.
pub fn ingress_param(p: &IngressPipe) -> [u8; INGRESS_PARAM_LEN] {
    let mut b = [0u8; INGRESS_PARAM_LEN];
    put(&mut b, 0, p.ep_type);
    put(&mut b, 8, u32::from(p.cs_offload));
    put(&mut b, 12, p.buff_size);
    put(&mut b, 16, p.agg_byte_limit);
    put(&mut b, 20, p.agg_time_limit);
    put(&mut b, 24, p.agg_pkt_limit);
    put(&mut b, 28, p.int_modt);
    put(&mut b, 32, p.int_modc);
    b
}

/// `struct egress_format_v2` and `struct ingress_format_v2`: the address of the array, the size of one
/// element and the number of elements.
pub fn format_v2(params_ptr: u64, param_size: u32, endpoints: u32) -> [u8; V2_LEN] {
    let mut b = [0u8; V2_LEN];
    put64(&mut b, 0, params_ptr);
    put(&mut b, 8, param_size);
    put(&mut b, 12, endpoints);
    b
}

/// `struct rmnet_ioctl_extended_s_v2`: the address of the format, its size and which format it is.
pub fn extended_v2(format_ptr: u64, format_size: u32, kind: u32) -> [u8; V2_LEN] {
    let mut b = [0u8; V2_LEN];
    put64(&mut b, 0, format_ptr);
    put(&mut b, 8, format_size);
    put(&mut b, 12, kind);
    b
}

/// The status the driver wrote into one element of an array of parameters (the second word of both).
pub fn status_of(param: &[u8]) -> PipeStatus {
    match get(param, 4) {
        0 => PipeStatus::Set,
        2 => PipeStatus::Existed,
        _ => PipeStatus::Failed,
    }
}

/// `EPERM`, what the ingress request answers when the WAN routing tables exist already.
const EPERM: i32 = 1;

/// What the driver wrote into the array of a format request: an endpoint that failed is an error also when the
/// ioctl returned 0 (`EIO`), and the pipes were up already when none was set up now and some existed. The
/// low latency control endpoint (`optional` is its type) is the one the driver goes on without when it fails
/// (the loops of `handle3_ingress_format_v2` and `handle3_egress_format_v2` `continue` past it), and the data
/// path does not need it, so a failure of that one entry is passed over.
pub fn outcome(params: &[u8], param_len: usize, optional: u32) -> Result<PipeStatus, NetError> {
    let mut existed = false;
    let mut set = false;
    for p in params.chunks_exact(param_len.max(1)) {
        match status_of(p) {
            PipeStatus::Failed if get(p, 0) == optional => {}
            PipeStatus::Failed => return Err(NetError::Os(5)),
            PipeStatus::Existed => existed = true,
            PipeStatus::Set => set = true,
        }
    }
    Ok(if existed && !set {
        PipeStatus::Existed
    } else {
        PipeStatus::Set
    })
}

/// The answer to the egress request: the ioctl's own result, then the statuses it wrote.
pub fn egress_result(rc: Result<(), NetError>, params: &[u8]) -> Result<PipeStatus, NetError> {
    rc?;
    outcome(params, EGRESS_PARAM_LEN, EgressPipe::LOW_LAT_CTRL)
}

/// The answer to the ingress request. A request that comes again finds the default and the coalescing pipe up,
/// writes `EXISTS` into the status of every pipe it knows and then returns `EPERM`, because the WAN routing
/// tables are there (`wan_rt_table_setup`). So `EPERM` with the data pipes reported up is the pipes being up
/// already. `EPERM` with anything else in the statuses stays the error it is.
pub fn ingress_result(rc: Result<(), NetError>, params: &[u8]) -> Result<PipeStatus, NetError> {
    match rc {
        Ok(()) => outcome(params, INGRESS_PARAM_LEN, IngressPipe::LOW_LAT_CTRL),
        Err(NetError::Os(EPERM)) if data_pipes_exist(params) => Ok(PipeStatus::Existed),
        Err(e) => Err(e),
    }
}

/// Does every default or coalescing entry say that its pipe is up already, and is there one?
fn data_pipes_exist(params: &[u8]) -> bool {
    let mut seen = false;
    for p in params.chunks_exact(INGRESS_PARAM_LEN) {
        let t = get(p, 0);
        if t == IngressPipe::DEFAULT || t == IngressPipe::COALESCING {
            if status_of(p) != PipeStatus::Existed {
                return false;
            }
            seen = true;
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(b: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn the_endpoint_comes_out_of_the_two_answers() {
        assert_eq!(word(&get_epid(), 0), 3);
        assert_eq!(word(&get_ep_pair(), 0), 0x10);
        let mut epid = get_epid();
        epid[4..8].copy_from_slice(&1u32.to_ne_bytes());
        let mut pair = get_ep_pair();
        pair[4..8].copy_from_slice(&2u32.to_ne_bytes());
        pair[8..12].copy_from_slice(&18u32.to_ne_bytes());
        assert_eq!(
            endpoint_of(&epid, &pair),
            Endpoint {
                epid: 1,
                consumer: 2,
                producer: 18
            }
        );
    }

    #[test]
    fn the_stock_format_is_two_egress_and_three_ingress_pipes() {
        let f = IpaFormat::default();
        assert_eq!(
            f.egress.iter().map(|p| p.ep_type).collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(
            f.ingress.iter().map(|p| p.ep_type).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        // the numbers of the trace: aggregation 64844 bytes, 500, 63 packets, buffer 16384
        let coal = &f.ingress[0];
        assert_eq!(
            (coal.agg_byte_limit, coal.agg_time_limit, coal.agg_pkt_limit),
            (64844, 500, 63)
        );
        assert_eq!(coal.buff_size, 16384);
        assert_eq!((f.egress[0].int_modt, f.egress[0].int_modc), (16, 20));
        assert_eq!((f.ingress[2].buff_size, f.ingress[2].int_modc), (4096, 1));
    }

    #[test]
    fn egress_parameter_layout() {
        let f = IpaFormat::default();
        let b = egress_param(&f.egress[0]);
        assert_eq!(b.len(), 32);
        let words: Vec<u32> = (0..8).map(|i| word(&b, i * 4)).collect();
        // type, status (the driver's), checksum offload, aggregation, ULSO, ipid index, int_modt, int_modc
        assert_eq!(words, [0, 0, 1, 1, 1, 0, 16, 20]);
        let low = egress_param(&f.egress[1]);
        assert_eq!(word(&low, 0), 1);
        assert_eq!(word(&low, 28), 1);
    }

    #[test]
    fn ingress_parameter_layout() {
        let f = IpaFormat::default();
        let b = ingress_param(&f.ingress[1]);
        assert_eq!(b.len(), 40);
        let words: Vec<u32> = (0..10).map(|i| word(&b, i * 4)).collect();
        // type, status, checksum offload, buffer, byte limit, time, packets, int_modt, int_modc, padding
        assert_eq!(words, [1, 0, 1, 16384, 64844, 500, 63, 16, 20, 0]);
        let ll = ingress_param(&f.ingress[2]);
        assert_eq!(
            (0..10).map(|i| word(&ll, i * 4)).collect::<Vec<_>>(),
            [2, 0, 0, 4096, 0, 0, 0, 16, 1, 0]
        );
    }

    #[test]
    fn the_v2_structures_have_the_layout_of_the_header() {
        let f = format_v2(0x1122_3344_5566_7788, 40, 3);
        assert_eq!(
            u64::from_ne_bytes(f[0..8].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        assert_eq!((word(&f, 8), word(&f, 12)), (40, 3));
        let e = extended_v2(0xaabb_ccdd, 16, V2_INGRESS);
        assert_eq!(u64::from_ne_bytes(e[0..8].try_into().unwrap()), 0xaabb_ccdd);
        assert_eq!((word(&e, 8), word(&e, 12)), (16, 1));
        assert_eq!(extended_v2(0, 16, V2_EGRESS)[12..], 0u32.to_ne_bytes());
    }

    #[test]
    fn the_status_the_driver_writes_back_is_read_from_the_second_word() {
        let mut p = [0u8; 40];
        assert_eq!(status_of(&p), PipeStatus::Set);
        p[4..8].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(status_of(&p), PipeStatus::Existed);
        p[4..8].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(status_of(&p), PipeStatus::Failed);
        p[4..8].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(
            status_of(&p),
            PipeStatus::Failed,
            "anything else is no success"
        );
    }

    /// Parameters of the ingress request with these (type, status) pairs, the rest of each zero.
    fn ingress_statuses(entries: &[(u32, u32)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(t, st)| {
                let mut p = [0u8; INGRESS_PARAM_LEN];
                p[0..4].copy_from_slice(&t.to_ne_bytes());
                p[4..8].copy_from_slice(&st.to_ne_bytes());
                p
            })
            .collect()
    }

    #[test]
    fn the_outcome_of_a_format_request_is_read_from_the_statuses_of_all_endpoints() {
        let mut two = [0u8; 80];
        assert_eq!(outcome(&two, 40, 2), Ok(PipeStatus::Set));
        // one up already and one set up now: something was done
        two[4..8].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(outcome(&two, 40, 2), Ok(PipeStatus::Set));
        // all up already
        two[44..48].copy_from_slice(&2u32.to_ne_bytes());
        assert_eq!(outcome(&two, 40, 2), Ok(PipeStatus::Existed));
        // one failed, whatever the others say, and whatever the ioctl returned
        two[44..48].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(outcome(&two, 40, 2), Err(NetError::Os(5)));
        assert_eq!(outcome(&[], 40, 2), Ok(PipeStatus::Set));
    }

    #[test]
    fn a_low_latency_control_pipe_that_failed_is_passed_over_and_no_other() {
        // the driver goes on past it, and the data path does not need it
        let ingress = ingress_statuses(&[(0, 0), (1, 0), (2, 1)]);
        assert_eq!(ingress_result(Ok(()), &ingress), Ok(PipeStatus::Set));
        let up = ingress_statuses(&[(0, 2), (1, 2), (2, 1)]);
        assert_eq!(ingress_result(Ok(()), &up), Ok(PipeStatus::Existed));
        for data in [0, 1] {
            let bad = ingress_statuses(&[(0, 0), (1, 0), (2, 0)])
                .chunks(INGRESS_PARAM_LEN)
                .enumerate()
                .flat_map(|(i, c)| {
                    let mut c = c.to_vec();
                    if i == data {
                        c[4..8].copy_from_slice(&1u32.to_ne_bytes());
                    }
                    c
                })
                .collect::<Vec<u8>>();
            assert_eq!(ingress_result(Ok(()), &bad), Err(NetError::Os(5)));
        }
        // the egress side: type 1 is the low latency control pipe
        let mut egress = vec![0u8; 2 * EGRESS_PARAM_LEN];
        egress[EGRESS_PARAM_LEN..EGRESS_PARAM_LEN + 4].copy_from_slice(&1u32.to_ne_bytes());
        egress[EGRESS_PARAM_LEN + 4..EGRESS_PARAM_LEN + 8].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(egress_result(Ok(()), &egress), Ok(PipeStatus::Set));
        egress[4..8].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(egress_result(Ok(()), &egress), Err(NetError::Os(5)));
        // the error of the ioctl itself wins
        assert_eq!(
            egress_result(Err(NetError::Os(12)), &[]),
            Err(NetError::Os(12))
        );
    }

    #[test]
    fn a_repeated_ingress_request_that_answers_eperm_with_the_pipes_up_is_the_pipes_being_up() {
        // The driver writes EXISTS into every status, copies the array back and then returns EPERM
        // because the WAN routing tables exist
        let eperm = Err(NetError::Os(1));
        let repeat = ingress_statuses(&[(0, 2), (1, 2), (2, 2)]);
        assert_eq!(ingress_result(eperm, &repeat), Ok(PipeStatus::Existed));
        // the low latency pipe may say anything, it does not decide
        let ll_set = ingress_statuses(&[(0, 2), (1, 2), (2, 0)]);
        assert_eq!(ingress_result(eperm, &ll_set), Ok(PipeStatus::Existed));
        // the same errno with a data pipe that is not reported up is not the pipes being up
        for bad in [
            ingress_statuses(&[(0, 0), (1, 2), (2, 2)]),
            ingress_statuses(&[(0, 2), (1, 1), (2, 2)]),
            // statuses as they were sent: the driver did not get as far as writing them
            ingress_statuses(&[(0, 0), (1, 0), (2, 0)]),
            // no data pipe among them
            ingress_statuses(&[(2, 2)]),
            Vec::new(),
        ] {
            assert_eq!(ingress_result(eperm, &bad), Err(NetError::Os(1)));
        }
        // other errors stay errors, also with every status up
        assert_eq!(
            ingress_result(Err(NetError::Os(14)), &repeat),
            Err(NetError::Os(14))
        );
        assert_eq!(
            ingress_result(Err(NetError::TimedOut), &repeat),
            Err(NetError::TimedOut)
        );
    }

    #[test]
    fn mux_channel_layout() {
        let b = add_mux_channel(7, "rmnet_data6").unwrap();
        assert_eq!(word(&b, 0), EXT_ADD_MUX_CHANNEL);
        assert_eq!(word(&b, 4), 7);
        assert_eq!(&b[8..19], b"rmnet_data6");
        assert!(b[19..].iter().all(|x| *x == 0), "NUL padded");
        // longest name that keeps a terminating NUL
        assert!(add_mux_channel(1, "fifteen_chars_x").is_ok());
        for bad in ["", "sixteen_chars_xx", "a\0b"] {
            assert_eq!(add_mux_channel(1, bad).unwrap_err(), BuildError::BadName);
        }
    }

    #[test]
    fn constants_match_the_uapi_header() {
        assert_eq!(RMNET_IOCTL_EXTENDED, 0x89F0 + 13);
        assert_eq!(RMNET_IOCTL_EXTENDED_V2, 0x89F0 + 14);
        assert_eq!(EXT_GET_EPID, 3);
        assert_eq!(EXT_ADD_MUX_CHANNEL, 5);
        assert_eq!(EXT_GET_EP_PAIR, 0x10);
        assert_eq!((V2_EGRESS, V2_INGRESS), (0, 1));
    }
}
