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
    h: [u8; 32],
}

impl Solution {
    /// Create a new solution
    pub fn new(digest: [u8; 16], nonce: [u8; 8]) -> Self {
        Self {
            d: digest,
            n: nonce,
            h: compute_hash(&digest, &nonce),
        }
    }

    /// Verify the solution against the raw `challenge || data || nonce`
    pub fn is_valid<const N: usize>(
        &self,
        challenge: &[u8; 32],
        data: &[u8; N],
    ) -> Result<(), CrankXError> {
        verify(challenge, data, &self.n, &self.d)
    }

    /// Final keccak(digest || nonce) hash (32 bytes)
    pub fn to_hash(&self) -> [u8; 32] {
        self.h
    }

    /// Compute the difficulty of the solution
    pub fn difficulty(&self) -> u32 {
        difficulty(self.h)
    }

    /// Serialize the solution to a byte array
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[..16].copy_from_slice(&self.d);
        bytes[16..].copy_from_slice(&self.n);
        bytes
    }

    /// Deserialize a byte array into a solution
    pub fn from_bytes(bytes: &[u8; 24]) -> Self {
        let mut d = [0; 16];
        let mut n = [0; 8];

        d.copy_from_slice(&bytes[..16]);
        n.copy_from_slice(&bytes[16..]);

        Self::new(d, n)
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

    Ok(Solution::new(digest, *nonce))
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

    Ok(Solution::new(digest, *nonce))
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
fn difficulty(hash: [u8; 32]) -> u32 {
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
fn build_seed<const N: usize>(
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
fn to_canonical(digest: &mut [u8; 16]) {
    unsafe {
        let words: &mut [u16; 8] = core::mem::transmute(digest);
        words.sort_unstable();
    }
}

/// Compute the final 32‑byte Keccak hash of the canonical digest and nonce
#[inline(always)]
fn compute_hash(digest: &[u8; 16], nonce: &[u8; 8]) -> [u8; 32] {
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
