use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

/// Struct to hold and process OLS data.
pub struct OlsConverter {
    ols_data: Vec<u8>, // Vector to store the contents of the OLS file.
}

impl OlsConverter {
    /// Constructor for `OlsConverter`.
    pub fn new() -> Self {
        OlsConverter {
            ols_data: Vec::new(),
        }
    }

    /// Finds the position immediately after a given pattern in the data starting from a specific index.
    /// Supports a wildcard byte (`0x99`) in the pattern that matches any byte.
    fn find_pattern_position_after(&self, data: &[u8], pattern: &[u8], start_index: usize) -> Option<usize> {
        let pattern_length = pattern.len();
        let data_length = data.len();

        // Return None if the pattern is empty or start index is beyond data length.
        if pattern_length == 0 || start_index >= data_length {
            return None;
        }

        // Iterate over the data to find the pattern.
        for i in start_index..=(data_length - pattern_length) {
            // Check if the pattern matches, considering 0x99 as a wildcard.
            if data[i..i + pattern_length]
                .iter()
                .zip(pattern)
                .all(|(a, &b)| *a == b || b == 0x99)
            {
                // Return the index immediately after the pattern.
                return Some(i + pattern_length);
            }
        }
        None
    }

    /// Removes all non-hexadecimal characters from a string and converts it to uppercase.
    fn convert_hex_string(&self, input: &str) -> String {
        input
            .chars()
            .filter(|c| c.is_ascii_hexdigit()) // Keep only hexadecimal digits.
            .collect::<String>()
            .to_uppercase()
    }

    /// Extracts the ECU size from the OLS file by searching for specific patterns.
    fn extract_ecu_size(&mut self, file_path: &str) -> Result<usize, std::io::Error> {
        let mut file = File::open(file_path)?;
        // Read the entire file into the `ols_data` vector.
        file.read_to_end(&mut self.ols_data)?;

        let windows_pattern = b"(Windows)\0"; // Pattern to search for in the OLS file.
        let separator_pattern = [0x00, 0x00, 0x00]; // Separator pattern used in WinOLS.

        // Find the position after the "(Windows)\0" pattern.
        let mut position = self.find_pattern_position_after(&self.ols_data, windows_pattern, 0);

        if position.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No (Windows) string found in OLS file",
            ));
        }

        let mut ecu_string_length = 0;

        // Search for the ECU size string by looking for multiple separator patterns.
        for i in 0..200 {
            if let Some(pos) =
                self.find_pattern_position_after(&self.ols_data, &separator_pattern, position.unwrap())
            {
                position = Some(pos + 1);
                // After several separators, the ECU size is indicated.
                if i >= 5 {
                    // The ECU size is stored 4 bytes before the current position.
                    ecu_string_length = self.ols_data[pos - 4];
                    if ecu_string_length > 0 {
                        break;
                    }
                }
            } else {
                break;
            }
        }

        // Calculate the position where the ECU size string starts.
        let ecu_size_position = position.unwrap() - 1;

        // Ensure we don't read beyond the buffer.
        if ecu_size_position + ecu_string_length as usize > self.ols_data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ECU size buffer out of bounds",
            ));
        }

        // Extract the ECU size string from the OLS data.
        let size_buffer = &self.ols_data[ecu_size_position..ecu_size_position + ecu_string_length as usize];
        let size_string = String::from_utf8_lossy(size_buffer);

        // Clean the size string to contain only hexadecimal characters.
        let cleaned_size_string = self.convert_hex_string(&size_string);
        // Parse the cleaned string as a hexadecimal number to get the ECU size.
        let ecu_size = usize::from_str_radix(&cleaned_size_string, 16).unwrap_or(0);

        println!("ECU size: {}h == {} bytes", size_string, ecu_size);

        Ok(ecu_size)
    }

    /// Converts the OLS file to a binary file by extracting the ECU binary data.
    pub fn convert_ols_to_bin(&mut self, file_path: &str, output_file_path: &str) -> Result<(), std::io::Error> {
        // Extract the ECU size from the OLS file.
        let ecu_size = self.extract_ecu_size(file_path)?;
        let ols_data_length = self.ols_data.len();

        // Ensure the ECU size is not larger than the file size.
        if ecu_size > ols_data_length {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ECU size is larger than file size"));
        }

        // Extract the ECU binary data from the OLS data.
        let ecu_binary_data = &self.ols_data[ols_data_length - ecu_size..];

        // Write the ECU binary data to the output file.
        let mut output_file = File::create(output_file_path)?;
        output_file.write_all(ecu_binary_data)?;

        println!("Conversion successful! Data written to {}", output_file_path);

        Ok(())
    }
}

fn main() {
    // Collect command-line arguments.
    let args: Vec<String> = env::args().collect();

    // Ensure the correct number of arguments are provided.
    if args.len() != 3 {
        eprintln!("Usage: {} <input_file_path> <output_file_path>", args[0]);
        process::exit(1);
    }

    let input_file_path = &args[1];
    let output_file_path = &args[2];

    // Create an instance of `OlsConverter`.
    let mut converter = OlsConverter::new();

    // Attempt to convert the OLS file to a binary file.
    if let Err(e) = converter.convert_ols_to_bin(input_file_path, output_file_path) {
        eprintln!("Failed to convert file: {}", e);
        process::exit(1);
    }
}
