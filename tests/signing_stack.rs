//! Regression test for the ML-DSA large-stack signing guard.
//!
//! Exercises the shared [`metamorphic_crypto::on_signing_stack`] guard end to end
//! at the two security levels that matter for the downstream NIFs — Cat-3
//! (ML-DSA-65) and Cat-5 (ML-DSA-87, the largest / heaviest-stack parameter set).
//! Keygen, signing and verification all run *inside* the guarded worker thread,
//! mirroring exactly how the BEAM NIFs invoke it on the dirty-CPU scheduler. If
//! the stack reservation were insufficient this would fault rather than return.

use metamorphic_crypto::{
    SignatureLevel, generate_signing_keypair_with_level, on_signing_stack, sign, verify,
};

fn roundtrip_on_guarded_stack(level: SignatureLevel) {
    let ok = on_signing_stack(move || {
        let keypair = generate_signing_keypair_with_level(level);
        let message = b"metamorphic large-stack signing regression";
        let context = "metamorphic.signing-stack-test";
        let signature = sign(message, context, &keypair.secret_key)
            .expect("ML-DSA hybrid sign should succeed on the guarded stack");
        verify(message, context, &signature, &keypair.public_key).expect("verify should not error")
    });

    assert!(ok, "hybrid signature must verify for {level:?}");
}

#[test]
fn signs_and_verifies_cat3_on_guarded_stack() {
    roundtrip_on_guarded_stack(SignatureLevel::Cat3);
}

#[test]
fn signs_and_verifies_cat5_on_guarded_stack() {
    roundtrip_on_guarded_stack(SignatureLevel::Cat5);
}
