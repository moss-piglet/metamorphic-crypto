//! Large-stack execution guard for lattice signing/keygen.
//!
//! ML-DSA (the FIPS 204 module-lattice signature) allocates large intermediate
//! working sets *on the stack* inside the upstream `ml-dsa` crate: the hedged
//! signing path expands the public matrix `A` and buffers several polynomial
//! vectors through its rejection-sampling loop, and key generation / verifying-key
//! expansion do the same. Those arrays are fixed-size stack allocations in code we
//! do not control (`ml-dsa`), so they cannot be boxed onto the heap from this
//! crate.
//!
//! On runtimes with a small thread stack this overflows and faults the guard page.
//! The two constrained runtimes we ship into have different characteristics:
//!
//! * **BEAM dirty-CPU scheduler** (via the Elixir NIFs): the dirty scheduler
//!   thread's default stack (`+sssdcpu`, ~320 KB) is far too small and the whole
//!   VM dies with SIGBUS. This module provides the fix: run the operation on a
//!   dedicated worker thread with a generous stack and block the scheduler on the
//!   join — exactly the kind of bounded, blocking work dirty schedulers exist for.
//!
//! * **Browser WASM** (via [`crate::wasm`]): the shadow stack is a fixed,
//!   build-time size with no threads, so the fix there is a *linker* stack-size
//!   bump rather than a worker thread. That is why this module is gated
//!   `#[cfg(not(target_arch = "wasm32"))]` — see the crate's `.cargo/config.toml`
//!   for the WASM side.
//!
//! Every consumer that drives ML-DSA signing or keygen from a small-stack native
//! thread should route the call through [`on_signing_stack`] rather than
//! re-implementing the guard or pushing a `+sssdcpu` requirement onto its own
//! `vm.args`. Verification uses far less stack and does not need this.

/// Recommended stack size, in bytes, for a thread that runs ML-DSA signing or
/// key generation.
///
/// 32 MiB comfortably covers ML-DSA-87 (Cat-5, the largest parameter set) with
/// generous headroom against future footprint growth in the upstream `ml-dsa`
/// crate. The reservation is cheap: only pages actually touched are committed by
/// the OS, so an unused 32 MiB stack costs (virtually) nothing in RSS.
pub const RECOMMENDED_SIGNING_STACK_BYTES: usize = 32 * 1024 * 1024;

/// Run `f` on a dedicated worker thread with [`RECOMMENDED_SIGNING_STACK_BYTES`]
/// of stack, returning its value.
///
/// This is the shared, audited guard for ML-DSA signing / keygen on small-stack
/// native runtimes (notably the BEAM dirty-CPU scheduler). The calling thread
/// blocks on the worker's join, so this is synchronous from the caller's point of
/// view — it simply borrows a bigger stack for the duration of `f`.
///
/// The closure must return owned, `Send` values; keep any FFI term/handle
/// construction on the caller so only plain data crosses the thread boundary. If
/// `f` panics, the panic is propagated to the calling thread unchanged (via
/// [`std::panic::resume_unwind`]), so `catch_unwind` and NIF panic handling behave
/// exactly as if `f` had run inline.
///
/// # Panics
///
/// Panics if the worker thread cannot be spawned (e.g. the OS refuses the stack
/// reservation), or re-raises any panic that occurred inside `f`.
///
/// # Examples
///
/// ```
/// use metamorphic_crypto::on_signing_stack;
///
/// let sig = on_signing_stack(|| vec![0u8; 32]);
/// assert_eq!(sig.len(), 32);
/// ```
pub fn on_signing_stack<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(RECOMMENDED_SIGNING_STACK_BYTES)
            .spawn_scoped(scope, f)
            .expect("failed to spawn signing worker thread")
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    })
}
