use std::time::Instant;

use crankx::equix::SolverMemory;
use crankx::{
    solve_with_memory,
    Solution, 
    CrankXError
};

const SEGMENT_SIZE: usize = 128; // bytes
const DIFFICULTY: u32 = 8; // leading zero bits

fn main() -> Result<(), CrankXError> {
    let challenge = [0; 32];
    let data = [42; SEGMENT_SIZE];

    println!("DIFFICULTY: {DIFFICULTY}");
    println!("SEGMENT_SIZE: {SEGMENT_SIZE}");

    let work_timer = Instant::now();
    let solution = do_work(challenge, &data)?;
    let work_time = work_timer.elapsed().as_nanos();
    println!("Work done in {work_time} ns");

    let proof_timer = Instant::now();
    prove_work(&challenge, &data, &solution)?;
    let proof_time = proof_timer.elapsed().as_nanos();
    println!("Proof done in {proof_time} ns");

    println!("Ratio: {}x", work_time / proof_time);

    Ok(())
}

fn do_work<const N: usize>(
    challenge: [u8; 32],
    data: &[u8; N],
) -> Result<Solution, CrankXError> {
    let mut memory = SolverMemory::new();
    let mut nonce : u64 = 0;

    loop {
        if let Ok(solution) = solve_with_memory(
            &mut memory, &challenge, data, &nonce.to_le_bytes()) {

            if solution.difficulty() >= DIFFICULTY {
                return Ok(solution);
            }
        }

        nonce += 1;
    }
}

fn prove_work<const N: usize>(
    challenge: &[u8; 32],
    data: &[u8; N],
    solution: &Solution,
) -> Result<(), CrankXError> {

    solution.is_valid(challenge, data)?;

    if solution.difficulty() < DIFFICULTY {
        return Err(CrankXError::InvalidSolution);
    }
    Ok(())
}
