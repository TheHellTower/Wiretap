extern crate std;

use std::vec::Vec;

use super::*;

fn flow(path: &[u8]) -> FlowRecord<'_> {
    FlowRecord {
        timestamp: 133_000_000_000_000_000,
        flow: 0xDEAD_BEEF,
        inbound: false,
        ipv6: true,
        pid: 4242,
        protocol: 6,
        local_port: 51544,
        remote_port: 443,
        local_addr: [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        remote_addr: [
            0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x84, 0xE5,
        ],
        path,
    }
}

fn encode_flow(r: &FlowRecord<'_>) -> Vec<u8> {
    [&flow_header(r)[..], r.path].concat()
}

fn encode_data(flow: u64, inbound: bool, wire_len: u32, data: &[u8]) -> Vec<u8> {
    [
        &data_header(7, flow, inbound, wire_len, data.len())[..],
        data,
    ]
    .concat()
}

#[test]
fn records_round_trip() {
    let path: Vec<u8> = "\\device\\harddiskvolume3\\curl.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let f = flow(&path);
    let stream = [
        encode_flow(&f),
        encode_data(f.flow, true, 1500, b"HTTP/1.1 200 OK\r\n"),
    ]
    .concat();
    let decoded: Vec<_> = records(&stream).collect::<Result<_, _>>().unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0], Record::Flow(f));
    let Record::Data(d) = decoded[1] else {
        panic!("expected data")
    };
    assert_eq!(
        (d.flow, d.inbound, d.wire_len, d.data),
        (f.flow, true, 1500, &b"HTTP/1.1 200 OK\r\n"[..])
    );
    assert_eq!(records(&[]).count(), 0);
}

#[test]
fn malformed_records_are_rejected_without_panicking() {
    let good = encode_data(1, false, 4, b"abcd");
    let mut cases: Vec<Vec<u8>> = std::vec![
        std::vec![0],                      // truncated length
        std::vec![3, 0, 2, 0],             // length below header size
        good[..good.len() - 1].to_vec(),   // record longer than buffer
        encode_data(1, false, 3, b"abcd"), // capture larger than wire length
    ];
    let mut bad_kind = good.clone();
    bad_kind[2] = 9;
    cases.push(bad_kind);
    let mut odd_path = encode_flow(&flow(&[1, 2, 3]));
    odd_path[0] = u8::try_from(odd_path.len()).unwrap();
    cases.push(odd_path);
    let mut trailing = encode_flow(&flow(&[]));
    trailing.push(0);
    trailing[0] += 1;
    cases.push(trailing);
    let mut huge = good.clone();
    huge[0..2].copy_from_slice(&u16::MAX.to_le_bytes());
    cases.push(huge);
    for case in cases {
        let results: Vec<_> = records(&case).collect();
        assert!(matches!(results.last(), Some(Err(DecodeError))), "{case:?}");
    }
}

#[test]
fn ring_preserves_records_across_wraparound() {
    let mut ring = Ring::<64>::new();
    let mut out = [0u8; 64];
    for round in 0u8..50 {
        let record = [5, 0, round, round, round];
        assert!(ring.push(&[&record[..2], &record[2..]]));
        assert_eq!(ring.pop_into(&mut out), 5);
        assert_eq!(out[..5], record);
        assert!(ring.is_empty());
    }
}

#[test]
fn ring_drops_when_full_and_pops_only_whole_records() {
    let mut ring = Ring::<32>::new();
    let record = [10, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    assert!(ring.push(&[&record]));
    assert!(ring.push(&[&record]));
    assert!(ring.push(&[&record]));
    assert!(!ring.push(&[&record]), "only 2 bytes free");
    assert!(!ring.push(&[]), "empty records are rejected");
    assert_eq!(ring.take_dropped(), 2);
    assert_eq!(ring.take_dropped(), 0);

    let mut small = [0u8; 15];
    assert_eq!(ring.pop_into(&mut small), 10, "second record does not fit");
    let mut big = [0u8; 64];
    assert_eq!(ring.pop_into(&mut big), 20);
    assert!(ring.is_empty());
    assert_eq!(ring.pop_into(&mut big), 0);
}

#[test]
fn ring_round_trips_driver_records() {
    let mut ring = Ring::<4096>::new();
    let path = [0x41, 0];
    let f = flow(&path);
    let data = [0x16u8, 3, 1];
    let mut written = 0;
    for _ in 0..100 {
        let dh = data_header(1, 2, false, 3, data.len());
        let fh = flow_header(&f);
        assert!(ring.push(&[&fh, &path]));
        assert!(ring.push(&[&dh, &data]));
        let mut out = [0u8; 4096];
        let n = ring.pop_into(&mut out);
        written += n;
        let decoded: Vec<_> = records(&out[..n]).collect::<Result<_, _>>().unwrap();
        assert_eq!(decoded.len(), 2);
    }
    assert!(written > 4096, "exercised wraparound");
}

#[test]
fn flow_budget_limits_each_direction() {
    let mut budget = FlowBudget::<8>::new();
    budget.reset(42);
    assert_eq!(budget.grant(42, false, 600, 1000), 600);
    assert_eq!(budget.grant(42, false, 600, 1000), 400);
    assert_eq!(budget.grant(42, false, 600, 1000), 0);
    assert_eq!(
        budget.grant(42, true, 5000, 1000),
        1000,
        "directions are independent"
    );
    budget.reset(42);
    assert_eq!(
        budget.grant(42, false, 10, 1000),
        10,
        "reset restores the budget"
    );
    assert_eq!(budget.grant(7, false, usize::MAX, 1000), 1000);
}

#[test]
fn flow_budget_eviction_is_bounded() {
    let mut budget = FlowBudget::<1>::new();
    assert_eq!(budget.grant(1, false, 100, 100), 100);
    assert_eq!(budget.grant(2, false, 100, 100), 100, "evicts flow 1");
    assert_eq!(
        budget.grant(1, false, 100, 100),
        100,
        "flow 1 restarts after eviction"
    );
    let mut empty = FlowBudget::<0>::new();
    assert_eq!(empty.grant(1, false, 100, 100), 0);
}

#[test]
fn ioctl_codes_match_ctl_code_layout() {
    assert_eq!(IOCTL_GET_VERSION, 0x8A71_6000);
    assert_eq!(IOCTL_READ_EVENTS, 0x8A71_6004);
    assert_eq!(
        IOCTL_SET_REDIRECT, 0x8A71_A008,
        "write access, function 0x802, buffered"
    );
}

#[test]
fn clear_discards_records_and_drops() {
    let mut ring = Ring::<16>::new();
    assert!(ring.push(&[&[10, 0, 1, 2, 3, 4, 5, 6, 7, 8]]));
    assert!(!ring.push(&[&[10, 0, 1, 2, 3, 4, 5, 6, 7, 8]]));
    ring.clear();
    assert!(ring.is_empty());
    assert_eq!(ring.take_dropped(), 0);
    assert!(ring.push(&[&[3, 0, 9]]), "space is reusable after clear");
}

#[test]
fn redirect_records_round_trip_and_reject_garbage() {
    let r = Redirect {
        pid: 4242,
        port_v4: 8899,
        port_v6: 8899,
    };
    assert_eq!(Redirect::decode(&r.encode()), Some(Some(r)));
    assert_eq!(
        Redirect::decode(&[0; 8]),
        Some(None),
        "all zero stops redirecting"
    );
    assert_eq!(Redirect::decode(&Redirect { pid: 0, ..r }.encode()), None);
    assert_eq!(
        Redirect::decode(
            &Redirect {
                port_v4: 0,
                port_v6: 0,
                ..r
            }
            .encode()
        ),
        None
    );
    assert_eq!(Redirect::decode(&[1; 7]), None);
    let o = Original {
        pid: 7,
        ipv6: false,
        port: 443,
        addr: [93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    let bytes = o.encode();
    assert_eq!(Original::decode(&bytes), Some(o));
    assert_eq!(
        bytes.get(10..12),
        Some(&[1, 187][..]),
        "port in network order"
    );
    for bad in [&bytes[..27], &[0u8; 28][..]] {
        assert_eq!(Original::decode(bad), None);
    }
    let mut wrong_family = bytes;
    wrong_family[8] = 5;
    assert_eq!(Original::decode(&wrong_family), None);
}
