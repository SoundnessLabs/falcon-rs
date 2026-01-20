use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap();
    let is_wasm = target.contains("wasm");
    let is_emscripten = target.contains("emscripten");

    let mut build = cc::Build::new();

    // For WASM targets, configure the compiler
    if is_wasm {
        if let Ok(emsdk) = env::var("EMSDK") {
            if is_emscripten {
                // Use emcc directly for emscripten targets
                let emcc = format!("{}/upstream/emscripten/emcc", emsdk);
                build.compiler(&emcc);
            } else {
                // For wasm32-unknown-unknown, use clang with emscripten sysroot
                let clang = format!("{}/upstream/bin/clang", emsdk);
                let sysroot = format!("{}/upstream/emscripten/cache/sysroot", emsdk);

                if PathBuf::from(&clang).exists() {
                    build.compiler(&clang);
                    build.flag(&format!("--sysroot={}", sysroot));
                    // Need to include emscripten's libc headers
                    build.include(format!("{}/include", sysroot));
                }
            }
        } else if is_emscripten {
            // Fall back to expecting emcc in PATH
            build.compiler("emcc");
        }
    }

    // Core source files
    build
        .file("c/falcon.c")
        .file("c/codec.c")
        .file("c/common.c")
        .file("c/fft.c")
        .file("c/fpr.c")
        .file("c/keygen.c")
        .file("c/rng.c")
        .file("c/shake.c")
        .file("c/sign.c")
        .file("c/vrfy.c")
        .include("c");

    // Common defines
    build.define("FALCON_PREFIX", "falcon_inner");

    if is_wasm {
        // WASM-specific configuration
        build
            // Disable platform-specific optimizations
            .define("FALCON_AVX2", "0")
            .define("FALCON_FMA", "0")
            .define("FALCON_ASM_CORTEXM4", "0")
            // Disable system RNG sources (WASM has no /dev/urandom)
            .define("FALCON_RAND_GETENTROPY", "0")
            .define("FALCON_RAND_URANDOM", "0")
            .define("FALCON_RAND_WIN32", "0")
            // WASM is little-endian but may not allow unaligned access
            .define("FALCON_LE", "1")
            .define("FALCON_UNALIGNED", "0")
            // Use native FP (WASM has IEEE-754 f64 support)
            .define("FALCON_FPEMU", "0")
            .define("FALCON_FPNATIVE", "1");
    } else {
        // Native builds
        // Disable system RNG by default for deterministic seeding control
        // (can be overridden with feature flags)
        if !cfg!(feature = "system-rng") {
            build
                .define("FALCON_RAND_GETENTROPY", "0")
                .define("FALCON_RAND_URANDOM", "0")
                .define("FALCON_RAND_WIN32", "0");
        }

        // Enable AVX2 if feature is set and target supports it
        if cfg!(feature = "avx2") && target.contains("x86_64") {
            build.define("FALCON_AVX2", "1");
            if cfg!(feature = "fma") {
                build.define("FALCON_FMA", "1");
            }
        } else {
            build.define("FALCON_AVX2", "0");
        }

        // Disable ARM assembly on non-ARM targets
        if !target.contains("arm") && !target.contains("aarch64") {
            build.define("FALCON_ASM_CORTEXM4", "0");
        }
    }

    // Optimization flags
    build.opt_level(3);

    // Compile
    build.compile("falcon");

    // Rerun if C source changes
    println!("cargo:rerun-if-changed=c/");
}
