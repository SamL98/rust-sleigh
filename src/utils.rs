pub fn parse_int(input: &str) -> u64 {
	if input.starts_with("0x") {
        u64::from_str_radix(&input[2..], 16).unwrap()
    } else if input.starts_with("0b") {
        u64::from_str_radix(&input[2..], 2).unwrap()
    } else {
        input.parse().unwrap()
    }
}
