use std::{collections::HashMap, env::current_dir, fs::File, io::Read, path::PathBuf};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{generate_witness_from_wasm, r1cs::CircomConfig, synthesize, witness};
use num_traits::ToPrimitive;
use rust_witness::{witness, BigInt};
use spartan2::traits::circuit::SpartanCircuit;
use tracing::info;

use crate::{Scalar, E};

// jwt.circom
witness!(main);
#[derive(Debug, Clone)]
pub struct JWTCircuit;

impl SpartanCircuit<E> for JWTCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let root = current_dir().unwrap().join("../circom");
        let witness_dir = root.join("build/jwt/jwt_js");
        let wtns = witness_dir.join("main.wasm");
        let r1cs = witness_dir.join("jwt.r1cs");

        let witness_input_json: String = {
            let path = current_dir()
                .unwrap()
                .join("../circom/inputs/jwt/default.json");
            let mut file = File::open(path).unwrap();
            let mut witness_input = String::new();
            file.read_to_string(&mut witness_input).unwrap();
            witness_input
        };

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

        let witness_circom_scotia: Vec<Scalar> = generate_witness_from_wasm(
            witness_dir,
            witness_input_json.clone(),
            PathBuf::from("output.wtns"),
        );
        dbg!(&witness_scalars.len());
        dbg!(&witness_circom_scotia.len());

        let cfg = CircomConfig::new(wtns, r1cs).unwrap();
        synthesize(cs, cfg.r1cs.clone(), Some(witness_scalars))?;
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
}
