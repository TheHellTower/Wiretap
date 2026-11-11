//! Standard base64 (RFC 4648, with padding). Decoding is strict.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes bytes.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let [a, b, c] = [0, 1, 2].map(|i| chunk.get(i).copied().unwrap_or(0));
        let n = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            let sextet = usize::try_from((n >> shift) & 63).unwrap_or(0);
            out.push(if i <= chunk.len() {
                char::from(ALPHABET.get(sextet).copied().unwrap_or(b'A'))
            } else {
                '='
            });
        }
    }
    out
}

fn value(c: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|p| u32::try_from(p).ok())
}

/// Decodes padded base64; `None` on any invalid character, length or padding.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let (chunks, _) = bytes.as_chunks::<4>();
    let last = chunks.len().saturating_sub(1);
    for (index, chunk) in chunks.iter().enumerate() {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && index != last) {
            return None;
        }
        let mut n = 0u32;
        for &c in chunk.get(..4 - pad)? {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * u32::try_from(pad).ok()?;
        let decoded = n.to_be_bytes();
        let piece = decoded.get(1..4 - pad)?;
        // Reject non-canonical encodings (set bits in the padding).
        if pad > 0
            && decoded
                .get(4 - pad..)
                .is_some_and(|rest| rest.iter().any(|&b| b != 0))
        {
            return None;
        }
        out.extend_from_slice(piece);
    }
    Some(out)
}
