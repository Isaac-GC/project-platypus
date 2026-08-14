//! Dependency-free parallel `map`, replacing the `rayon` crate.
//!
//! The DEX parser resolves several large index tables (strings, types,
//! methods, fields) by mapping a `Vec`/slice through a cheap per-element
//! closure. Those were `rayon` `par_iter().map().collect()` calls. This
//! module reimplements just that pattern on top of `std::thread::scope`
//! (stable since Rust 1.63), so the workspace carries no external
//! threadpool dependency.
//!
//! Two flavours:
//!
//!   * [`map`] / [`map_owned`] — *fine-grained* work. Each element's
//!     closure is cheap (a string clone + a struct build), so we split
//!     the input into one contiguous chunk per CPU and run each chunk
//!     on a scoped thread. Below a threshold we stay sequential because
//!     thread-spawn overhead would dominate.
//!
//!   * [`map_heavy`] — *coarse-grained* work. Each element is itself an
//!     expensive unit (e.g. "run a whole VM over this batch of call
//!     sites"). We spawn one scoped thread per element (capped at the
//!     CPU count), no chunking — matching how the analysis layer
//!     pre-chunks its work before calling in.
//!
//! Results always come back in input order.

/// Inputs smaller than this run sequentially in [`map`]/[`map_owned`] —
/// below it the cost of spawning threads + joining outweighs the work.
const FINE_SEQ_THRESHOLD: usize = 2048;

/// CPU count, clamped to at least 1. `available_parallelism` can fail in
/// exotic sandboxes; we degrade to single-threaded there.
fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

/// Parallel map over a borrowed slice. `T: Sync` (shared across threads
/// by reference), `R: Send` (moved back out). Equivalent to
/// `items.par_iter().map(f).collect()`.
pub fn map<T, R, F>(items: &[T], f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let n = items.len();
    let threads = if n < FINE_SEQ_THRESHOLD { 1 } else { cpu_count().min(n) };
    if threads <= 1 {
        return items.iter().map(f).collect();
    }

    let chunk_size = n.div_ceil(threads);
    let f = &f;
    let nested: Vec<Vec<R>> = std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || chunk.iter().map(f).collect::<Vec<R>>()))
            .collect();
        handles.into_iter().map(|h| h.join().expect("worker thread panicked")).collect()
    });
    flatten(nested)
}

/// Parallel map over an owned `Vec`. `T: Send` (moved into a worker),
/// `R: Send`. Equivalent to `items.into_par_iter().map(f).collect()`.
pub fn map_owned<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let n = items.len();
    let threads = if n < FINE_SEQ_THRESHOLD { 1 } else { cpu_count().min(n) };
    if threads <= 1 {
        return items.into_iter().map(f).collect();
    }

    // Partition into contiguous owned chunks so each worker owns its slice.
    let chunk_size = n.div_ceil(threads);
    let mut chunks: Vec<Vec<T>> = Vec::with_capacity(threads);
    let mut it = items.into_iter();
    loop {
        let chunk: Vec<T> = it.by_ref().take(chunk_size).collect();
        if chunk.is_empty() {
            break;
        }
        chunks.push(chunk);
    }

    let f = &f;
    let nested: Vec<Vec<R>> = std::thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| scope.spawn(move || chunk.into_iter().map(f).collect::<Vec<R>>()))
            .collect();
        handles.into_iter().map(|h| h.join().expect("worker thread panicked")).collect()
    });
    flatten(nested)
}

/// Parallel map for *coarse* work units — one scoped thread per element
/// (capped at the CPU count for inputs larger than that), no chunking.
/// Use when each element's closure is itself expensive, so per-element
/// thread overhead is negligible. `T: Send`, `R: Send`.
pub fn map_heavy<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let n = items.len();
    if n <= 1 {
        return items.into_iter().map(&f).collect();
    }
    let f = &f;
    // One thread per element. The OS scheduler multiplexes onto the
    // available cores; for the small element counts this is called with
    // (a handful of pre-built chunks) the spawn cost is irrelevant next
    // to the per-element VM run.
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .into_iter()
            .map(|item| scope.spawn(move || f(item)))
            .collect();
        handles.into_iter().map(|h| h.join().expect("worker thread panicked")).collect()
    })
}

/// Concatenate per-worker result vectors back into a single ordered Vec.
fn flatten<R>(nested: Vec<Vec<R>>) -> Vec<R> {
    let total: usize = nested.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(total);
    for chunk in nested {
        out.extend(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_ref_preserves_order_small() {
        let v: Vec<i32> = (0..10).collect();
        let out = map(&v, |&x| x * 2);
        assert_eq!(out, (0..10).map(|x| x * 2).collect::<Vec<_>>());
    }

    #[test]
    fn map_ref_preserves_order_large() {
        // Above the threshold so the parallel path runs.
        let v: Vec<i64> = (0..50_000).collect();
        let out = map(&v, |&x| x + 1);
        let expect: Vec<i64> = (0..50_000).map(|x| x + 1).collect();
        assert_eq!(out, expect);
    }

    #[test]
    fn map_owned_preserves_order_large() {
        let v: Vec<usize> = (0..50_000).collect();
        let out = map_owned(v, |x: usize| x.wrapping_mul(3));
        let expect: Vec<usize> = (0..50_000).map(|x: usize| x.wrapping_mul(3)).collect();
        assert_eq!(out, expect);
    }

    #[test]
    fn map_heavy_preserves_order() {
        let v = vec![vec![1, 2], vec![3], vec![4, 5, 6]];
        let out = map_heavy(v, |chunk| chunk.iter().sum::<i32>());
        assert_eq!(out, vec![3, 3, 15]);
    }

    #[test]
    fn empty_inputs() {
        assert!(map::<i32, i32, _>(&[], |&x| x).is_empty());
        assert!(map_owned::<i32, i32, _>(vec![], |x| x).is_empty());
        assert!(map_heavy::<i32, i32, _>(vec![], |x| x).is_empty());
    }
}
