use falcon::{Falcon1024, Falcon512, KeyPair, SignatureFormat};

fn main() {
    println!("Testing Falcon-512 implementation...\n");

    let seed = [0x42u8; 48];
    println!("Seed: {}\n", hex::encode(&seed));

    // Generate keypair from seed
    let keypair =
        KeyPair::<Falcon512>::generate_from_seed(&seed).expect("Failed to generate keypair");
    println!("✓ Generated keypair from seed");

    // Display keypair
    let public_key = keypair.public_key();
    let public_key_bytes = public_key.as_bytes();
    println!("  Public Key length: {} bytes", public_key_bytes.len());
    println!("  Public Key (hex): {}\n", hex::encode(public_key_bytes));

    // Sign a message with compressed signature
    let message = b"message";
    let signature = keypair
        .sign_with_seed(message, SignatureFormat::Compressed, &seed)
        .expect("Failed to sign message");
    println!("✓ Signed message with compressed format");
    println!("  Message: {:?}", String::from_utf8_lossy(message));
    println!("  Signature length: {} bytes", signature.len());
    println!("  Signature (hex): {}\n", hex::encode(&signature));

    // Verify signature
    let is_valid = keypair
        .public_key()
        .verify(message, &signature)
        .expect("Verification failed");
    assert!(is_valid, "Signature verification failed!");
    println!("✓ Signature verification passed\n");

    // Test with padded format
    let signature_padded = keypair
        .sign_with_seed(message, SignatureFormat::Padded, &seed)
        .expect("Failed to sign with padded format");
    println!("✓ Signed message with padded format");
    println!("  Signature length: {} bytes", signature_padded.len());
    println!("  Signature (hex): {}\n", hex::encode(&signature_padded));

    assert!(keypair
        .public_key()
        .verify(message, &signature_padded)
        .expect("Verification failed!"));
    println!("✓ Padded signature verification passed\n");

    // Test with different message
    let different_message = b"different message";
    let sig_diff = keypair
        .sign_with_seed(different_message, SignatureFormat::Compressed, &seed)
        .expect("Failed to sign");
    println!("✓ Signed different message");
    println!(
        "  Message: {:?}",
        String::from_utf8_lossy(different_message)
    );
    println!("  Signature length: {} bytes", sig_diff.len());
    println!("  Signature (hex): {}\n", hex::encode(&sig_diff));

    assert!(keypair
        .public_key()
        .verify(different_message, &sig_diff)
        .expect("Verification failed!"));
    println!("✓ Different message verified\n");

    // Verify wrong message fails
    let wrong_verify = keypair
        .public_key()
        .verify(b"wrong", &signature)
        .expect("Verification check failed!");
    assert!(!wrong_verify, "Should not verify wrong message!");
    println!("✓ Correctly rejected invalid message\n");

    println!("✓ All tests passed!");
}
