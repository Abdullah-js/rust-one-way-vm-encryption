
use super::CompressionLevel;

pub struct CustomLzCompressor;

pub struct LzCompressor {
    level: CompressionLevel,
}

impl LzCompressor {
    pub fn new() -> Self {
        Self { level: CompressionLevel::Normal }
    }
    
    pub fn with_level(level: CompressionLevel) -> Self {
        Self { level }
    }
    
    pub fn compress(&self, data: &[u8]) -> Vec<u8> {
        CustomLzCompressor::compress(data, self.level)
    }
    
    pub fn decompress(&self, data: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
        CustomLzCompressor::decompress(data, expected_size)
    }
}

impl CustomLzCompressor {
    pub fn compress(input: &[u8], level: CompressionLevel) -> Vec<u8> {
        if input.is_empty() {
            return vec![];
        }
        
        let window_size = match level {
            CompressionLevel::Fast => 256,
            CompressionLevel::Normal => 4096,
            CompressionLevel::Maximum => 32768,
        };
        
        let min_match = 3;
        let max_match = 258;
        
        let mut output = Vec::new();
        let mut pos = 0;
        let mut literals = Vec::new();
        
        while pos < input.len() {
            // Find best match in sliding window
            let (match_offset, match_length) = Self::find_match(
                input,
                pos,
                window_size,
                min_match,
                max_match,
            );
            
            if match_length >= min_match {
                // Flush literals first
                if !literals.is_empty() {
                    Self::encode_literals(&mut output, &literals);
                    literals.clear();
                }
                
                // Encode match
                Self::encode_match(&mut output, match_offset, match_length);
                pos += match_length;
            } else {
                // Add to literals
                literals.push(input[pos]);
                pos += 1;
                
                // Flush if too many literals
                if literals.len() >= 127 {
                    Self::encode_literals(&mut output, &literals);
                    literals.clear();
                }
            }
        }
        
        // Flush remaining literals
        if !literals.is_empty() {
            Self::encode_literals(&mut output, &literals);
        }
        
        // End marker
        output.push(0x00);
        
        output
    }
    
    pub fn decompress(input: &[u8], expected_size: usize) -> Result<Vec<u8>, String> {
        let mut output = Vec::with_capacity(expected_size);
        let mut pos = 0;
        
        while pos < input.len() {
            let tag = input[pos];
            pos += 1;
            
            if tag == 0x00 {
                // End marker
                break;
            } else if tag & 0x80 == 0 {
                // Literals: tag encodes length (1-127)
                let length = (tag & 0x7F) as usize;
                if pos + length > input.len() {
                    return Err("Truncated literals".into());
                }
                output.extend_from_slice(&input[pos..pos + length]);
                pos += length;
            } else {
                // Match: decode offset and length
                let (offset, length, bytes_read) = Self::decode_match(&input[pos - 1..])?;
                pos += bytes_read - 1;
                
                if offset > output.len() {
                    return Err("Invalid match offset".into());
                }
                
                let start = output.len() - offset;
                for i in 0..length {
                    let byte = output[start + (i % offset)];
                    output.push(byte);
                }
            }
        }
        
        Ok(output)
    }
    
    fn find_match(
        input: &[u8],
        pos: usize,
        window_size: usize,
        min_match: usize,
        max_match: usize,
    ) -> (usize, usize) {
        let mut best_offset = 0;
        let mut best_length = 0;
        
        let start = if pos > window_size { pos - window_size } else { 0 };
        
        for window_pos in start..pos {
            let mut length = 0;
            while pos + length < input.len()
                && length < max_match
                && input[window_pos + (length % (pos - window_pos))] == input[pos + length]
            {
                length += 1;
            }
            
            if length >= min_match && length > best_length {
                best_offset = pos - window_pos;
                best_length = length;
            }
        }
        
        (best_offset, best_length)
    }
    
    fn encode_literals(output: &mut Vec<u8>, literals: &[u8]) {
        // Tag byte: 0xxxxxxx where x = length - 1
        let length = literals.len();
        output.push((length & 0x7F) as u8);
        output.extend_from_slice(literals);
    }
    
    fn encode_match(output: &mut Vec<u8>, offset: usize, length: usize) {
        // Tag byte: 1xxxxxxx
        // Encoding depends on offset/length size
        
        if offset <= 255 && length <= 15 {
            // Short match: 1000LLLL OOOOOOOO
            output.push(0x80 | ((length - 3) as u8 & 0x0F));
            output.push(offset as u8);
        } else if offset <= 65535 && length <= 63 {
            // Medium match: 1001LLLL LLOOOOOO OOOOOOOO
            let len_enc = (length - 3) & 0x3F;
            output.push(0x90 | ((len_enc >> 2) as u8 & 0x0F));
            output.push((((len_enc & 0x03) << 6) | ((offset >> 8) & 0x3F)) as u8);
            output.push((offset & 0xFF) as u8);
        } else {
            // Long match: 1010LLLL LLLLLLLL OOOOOOOO OOOOOOOO
            let len_enc = (length - 3) & 0xFFF;
            output.push(0xA0 | ((len_enc >> 8) as u8 & 0x0F));
            output.push((len_enc & 0xFF) as u8);
            output.push((offset >> 8) as u8);
            output.push((offset & 0xFF) as u8);
        }
    }
    
    fn decode_match(input: &[u8]) -> Result<(usize, usize, usize), String> {
        if input.is_empty() {
            return Err("Empty match data".into());
        }
        
        let tag = input[0];
        let match_type = (tag >> 4) & 0x0F;
        
        match match_type {
            0x8 => {
                // Short match
                if input.len() < 2 {
                    return Err("Truncated short match".into());
                }
                let length = ((tag & 0x0F) + 3) as usize;
                let offset = input[1] as usize;
                Ok((offset, length, 2))
            }
            0x9 => {
                // Medium match
                if input.len() < 3 {
                    return Err("Truncated medium match".into());
                }
                let len_high = (tag & 0x0F) as usize;
                let len_low = (input[1] >> 6) as usize;
                let length = ((len_high << 2) | len_low) + 3;
                let offset = (((input[1] & 0x3F) as usize) << 8) | (input[2] as usize);
                Ok((offset, length, 3))
            }
            0xA => {
                // Long match
                if input.len() < 4 {
                    return Err("Truncated long match".into());
                }
                let length = (((tag & 0x0F) as usize) << 8 | (input[1] as usize)) + 3;
                let offset = ((input[2] as usize) << 8) | (input[3] as usize);
                Ok((offset, length, 4))
            }
            _ => Err("Unknown match type".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compress_decompress() {
        let original = b"Hello, World! Hello, World! Hello, World!";
        let compressed = CustomLzCompressor::compress(original, CompressionLevel::Normal);
        let decompressed = CustomLzCompressor::decompress(&compressed, original.len()).unwrap();
        assert_eq!(original.to_vec(), decompressed);
    }
}
