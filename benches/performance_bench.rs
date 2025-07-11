use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rscan::utils::performance::*;
use std::time::Duration;
use std::net::IpAddr;
use std::str::FromStr;

fn cache_benchmark(c: &mut Criterion) {
    let cache = SimpleCache::<String, String>::new(1000, Duration::from_secs(60));
    
    c.bench_function("cache_insert", |b| {
        b.iter(|| {
            for i in 0..100 {
                cache.insert(
                    black_box(format!("key_{}", i)),
                    black_box(format!("value_{}", i))
                );
            }
        })
    });
    
    // Pre-populate cache for get benchmark
    for i in 0..100 {
        cache.insert(format!("key_{}", i), format!("value_{}", i));
    }
    
    c.bench_function("cache_get", |b| {
        b.iter(|| {
            for i in 0..100 {
                let _ = cache.get(&black_box(format!("key_{}", i)));
            }
        })
    });
}

fn rate_limiter_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let limiter = RateLimiter::new(10, 100.0);
    
    c.bench_function("rate_limiter_acquire", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _permit = limiter.acquire().await;
                black_box(());
            })
        })
    });
}

fn object_pool_benchmark(c: &mut Criterion) {
    let pool = ObjectPool::new(|| Vec::<u8>::with_capacity(1024), 100);
    
    c.bench_function("object_pool_get_return", |b| {
        b.iter(|| {
            let obj = pool.get();
            black_box(&obj);
            pool.return_object(obj);
        })
    });
}

fn batch_processor_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let processor = BatchProcessor::<i32>::new(50, Duration::from_millis(100));
    
    c.bench_function("batch_processor_add", |b| {
        b.iter(|| {
            rt.block_on(async {
                for i in 0..100 {
                    let _ = processor.add(black_box(i)).await;
                }
            })
        })
    });
}

// Network utilities benchmark
fn network_utils_benchmark(c: &mut Criterion) {
    use rscan::utils::network::*;
    
    let ip = IpAddr::from_str("192.168.1.1").unwrap();
    
    c.bench_function("is_private_ip", |b| {
        b.iter(|| {
            is_private_ip(&black_box(ip))
        })
    });
    
    c.bench_function("is_valid_scan_target", |b| {
        b.iter(|| {
            is_valid_scan_target(&black_box(ip))
        })
    });
}

criterion_group!(
    benches,
    cache_benchmark,
    rate_limiter_benchmark,
    object_pool_benchmark,
    batch_processor_benchmark,
    network_utils_benchmark
);
criterion_main!(benches);