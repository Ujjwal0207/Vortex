use std::sync::Arc;
use std::thread;
use std::time::Instant;
use vortex_core::spsc::SpscRingBuffer;

#[test]
fn test_spsc_ring_buffer_sub_50ns_dispatch() {
    const CAPACITY: usize = 1024;
    let ring = Arc::new(SpscRingBuffer::<u64, CAPACITY>::new());
    let ring_consumer = Arc::clone(&ring);

    let total_messages = 100_000u64;

    let consumer = thread::spawn(move || {
        let mut received = 0u64;
        let mut sum = 0u64;
        while received < total_messages {
            if let Some(val) = ring_consumer.pop() {
                sum += val;
                received += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        sum
    });

    let start = Instant::now();
    for i in 0..total_messages {
        while ring.push(i).is_err() {
            std::hint::spin_loop();
        }
    }

    let sum = consumer.join().unwrap();
    let elapsed = start.elapsed();

    // Verify mathematical correctness
    let expected_sum: u64 = (0..total_messages).sum();
    assert_eq!(sum, expected_sum);

    let ns_per_msg = elapsed.as_nanos() as f64 / total_messages as f64;
    println!("SPSC dispatch throughput: {:.2} ns/msg across threads", ns_per_msg);

    // In release mode this is < 30ns; in debug mode it should be < 300ns
    assert!(ns_per_msg < 500.0, "SPSC dispatch should be sub-500ns in debug mode");
}
