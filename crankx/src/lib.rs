// CrankX: proof-of-access mechanism for data stored on tape segments using EquiX PoW
// Verifies each tape segment by “cranking” a PoW puzzle tied to its raw bytes

// Loosely based on the Ore's drillx, but with added proof-of-access to data.

pub use equix;

#[cfg(not(feature = "solana"))]
use sha3::Digest;

/// Errors for PoW operations
#[derive(Debug)]
pub enum CrankXError {
    /// Failed to build or solve the EquiX puzzle
    EquiXFailure,
    /// No solution found for the given seed
    NoSolution,
    /// Invalid solution
    InvalidSolution,
}

impl core::fmt::Display for CrankXError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", match self {
            CrankXError::EquiXFailure => "EquiX build/solve failed",
            CrankXError::NoSolution   => "No EquiX solution found",
            CrankXError::InvalidSolution => "Invalid EquiX solution",
        })
    }
}

impl std::error::Error for CrankXError {}

#[derive(Default)]
pub struct Solution {
    /// Raw EquiX digest (16 bytes)
    pub d: [u8; 16],
    /// Nonce (8 bytes)
    pub n: [u8; 8],
    /// Final keccak(digest || nonce) hash (32 bytes)
    pub h: [u8; 32],
}

impl Solution {
    /// Number of leading zeros in `h`, indicating difficulty
    pub fn difficulty(&self) -> u32 {
        difficulty(self.h)
    }
}

/// Solve PoW over raw `challenge || data || nonce`
#[inline(always)]
pub fn solve<const N: usize>(
    challenge: &[u8; 32],
    data: &[u8; N],
    nonce: &[u8; 8],
) -> Result<Solution, CrankXError> {
    let seed = build_seed(challenge, data, nonce);

    let solutions = equix::solve(&seed)
        .map_err(|_| CrankXError::EquiXFailure)?;

    if solutions.is_empty() {
        return Err(CrankXError::NoSolution);
    }

    // Keep in mind that EquiX returns a slice of 16-byte digests, which is a unordered set of
    // indices. We need to sort them to prevent malleability.

    let digest = unsafe { solutions.get_unchecked(0) }.to_bytes();

    Ok(Solution { 
        d: digest, 
        n: *nonce,
        h: compute_hash(&digest, nonce)
    })
}

/// Solve PoW with pre‑allocated memory (for on‑chain performance)
#[inline(always)]
pub fn solve_with_memory<const N: usize>(
    mem: &mut equix::SolverMemory,
    challenge: &[u8; 32],
    data: &[u8; N],
    nonce: &[u8; 8],
) -> Result<Solution, CrankXError> {

    let seed = build_seed(challenge, data, nonce);

    let eq = equix::EquiXBuilder::new()
        .runtime(equix::RuntimeOption::TryCompile)
        .build(&seed)
        .map_err(|_| CrankXError::EquiXFailure)?;

    let solutions = eq.solve_with_memory(mem);
    if solutions.is_empty() {
        return Err(CrankXError::NoSolution);
    }

    let digest = unsafe { solutions.get_unchecked(0) }.to_bytes();

    Ok(Solution { 
        d: digest, 
        n: *nonce,
        h: compute_hash(&digest, nonce)
    })
}

/// Verify a candidate digest against raw `challenge || data || nonce`
#[inline(always)]
pub fn verify<const N: usize>(
    challenge: &[u8; 32],
    data: &[u8; N],
    nonce: &[u8; 8],
    digest: &[u8; 16],
) -> Result<(), CrankXError> {

    let seed = build_seed(challenge, data, nonce);

    equix::verify_bytes(&seed, digest)
        .map_err(|_| CrankXError::EquiXFailure)?;

    Ok(())
}

/// Count leading zeros in a 32‑byte hash
pub fn difficulty(hash: [u8; 32]) -> u32 {
    let mut count = 0;
    for &b in &hash {
        let lz = b.leading_zeros();
        count += lz;
        if lz < 8 {
            break;
        }
    }
    count
}

/// Build the seed: `challenge || data || nonce`
/// Includes full raw data to prove possession; no pre‑hash needed.
#[inline(always)]
pub fn build_seed<const N: usize>(
    challenge: &[u8; 32],
    data: &[u8; N],
    nonce: &[u8; 8],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(32 + N + 8);
    seed.extend_from_slice(challenge);
    seed.extend_from_slice(data);
    seed.extend_from_slice(nonce);
    seed
}

/// Sort 16‑byte digest as u16 words to prevent malleability
#[inline(always)]
pub fn to_canonical(digest: &mut [u8; 16]) {
    unsafe {
        let words: &mut [u16; 8] = core::mem::transmute(digest);
        words.sort_unstable();
    }
}

/// Compute the final 32‑byte Keccak hash of the canonical digest and nonce
#[inline(always)]
pub fn compute_hash(digest: &[u8; 16], nonce: &[u8; 8]) -> [u8; 32] {
    let mut d = *digest;
    to_canonical(&mut d);

    #[cfg(feature = "solana")]
    {
        solana_program::keccak::hashv(&[&d, nonce]).to_bytes()
    }
    #[cfg(not(feature = "solana"))]
    {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(&d);
        hasher.update(nonce);
        hasher.finalize().into()
    }
}
