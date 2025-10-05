//! Measure Spartan-2 {setup, gen_witness, prove, verify} times for either ECDSA or JWT circuits.
//!
//! Usage:
//!   RUST_LOG=info cargo run --release -- ecdsa
//!   RUST_LOG=info cargo run --release -- jwt
//!
//! To benchmark only the JWT circuit sum-check:
//!   RUST_LOG=info cargo run --release -- jwt_sum_check
//!
//! To benchmark only Spartan sum-check + Hyrax for ECDSA/JWT:
//!   RUST_LOG=info cargo run --release -- prove_jwt
//!   RUST_LOG=info cargo run --release -- prove_ecdsa

use crate::config_generator::{prove_ecdsa, prove_jwt, prove_sum_check_jwt};
use crate::ecdsa_circuit::ECDSACircuit;
use crate::jwt_circuit::JWTCircuit;
use crate::setup::{run_circuit, setup_ecdsa_keys, setup_jwt_chunked_keys, setup_jwt_keys};

use circom_scotia::generate_witness_from_wasm;
use num_traits::ToPrimitive;
use rust_witness::{witness, BigInt};
use spartan2::{provider::T256HyraxEngine, traits::Engine};
use std::collections::HashMap;
use std::env::args;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

mod config_generator;
mod ecdsa_circuit;
mod jwt_circuit;
mod setup;
witness!(main);

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let choice = args.get(1).map(|s| s.as_str()).unwrap_or("ecdsa");

    match choice {
        "setup-ecdsa" => {
            setup_ecdsa_keys();
        }
        "setup-jwt" => {
            setup_jwt_keys();
        }
        "setup-chunked-jwt" => {
            setup_jwt_chunked_keys();
        }

        "ecdsa" => {
            info!("Running ECDSA circuit");
            run_circuit(ECDSACircuit);
        }
        "jwt" => {
            info!("Running JWT circuit");
            run_circuit(JWTCircuit);
        }
        "jwt_sum_check" => {
            info!("Running JWT sum check circuit");
            prove_sum_check_jwt();
        }
        "prove_jwt" => {
            info!("Spartan sumcheck + Hyrax PCS JWT");
            prove_jwt();
        }
        "prove_ecdsa" => {
            info!("Spartan sumcheck + Hyrax PCS ECDSA");
            prove_ecdsa();
        }
        "test_witness" => {
            info!("Testing witness");
            test_witness();
        }
        other => {
            eprintln!("Unknown choice '{}'", other);
            std::process::exit(1);
        }
    }
}

use std::{env::current_dir, fs::File, io::Read, path::PathBuf};

fn test_witness() {
    let root = current_dir().unwrap().join("../circom");
    let witness_dir = root.join("build/jwt/jwt_js");

    let witness_input_json: String = {
        let path = current_dir()
            .unwrap()
            .join("../circom/inputs/jwt/default.json");
        let mut file = File::open(path).unwrap();
        let mut witness_input = String::new();
        file.read_to_string(&mut witness_input).unwrap();
        witness_input
    };

    let witness_circom_scotia: Vec<Scalar> = generate_witness_from_wasm(
        witness_dir,
        witness_input_json.clone(),
        PathBuf::from("output.wtns"),
    );

    info!(
        "witness_circom_scotia length: {}",
        witness_circom_scotia.len()
    );

    info!("------------rust witness generator---------------");

    let input_data: serde_json::Value = serde_json::from_str(&witness_input_json).unwrap();

    // Convert JSON input to HashMap<String, Vec<Scalar>> format
    let mut inputs_bigint: HashMap<String, Vec<BigInt>> = HashMap::new();

    if let Some(obj) = input_data.as_object() {
        for (key, value) in obj {
            match value {
                serde_json::Value::String(s) => {
                    // Parse string as BigInt first, then convert to Scalar
                    if let Ok(bigint) = s.parse::<BigInt>() {
                        inputs_bigint.insert(key.clone(), vec![bigint]);
                    }
                }
                serde_json::Value::Array(arr) => {
                    // Parse array of numbers as Vec<Scalar>
                    let mut scalars = Vec::new();
                    let mut bigints = Vec::new();
                    for item in arr {
                        if let Some(num) = item.as_u64() {
                            scalars.push(Scalar::from(num));
                            bigints.push(BigInt::from(num));
                        }
                    }
                    inputs_bigint.insert(key.clone(), bigints);
                }
                _ => {}
            }
        }
    }

    // Generate witness using rust-witness (replacing generate_witness_from_wasm)
    let witness_bigints = main_witness(inputs_bigint);

    // Convert Vec<BigInt> to Vec<Scalar>
    let witness_scalars: Vec<Scalar> = witness_bigints
        .into_iter()
        .filter_map(|bigint| bigint.to_u64().map(Scalar::from))
        .collect();

    // // assert_eq!(witness_scalars, witness_circom_scotia);
    // for i in 0..witness_scalars.len() {
    //     print!("index {}", i);
    //     assert_eq!(witness_scalars[i], witness_circom_scotia[i]);
    //     println!("");
    // }
    info!("witness_scalars length: {}", witness_scalars.len());
}
