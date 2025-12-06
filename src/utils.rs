pub fn parse_int(input: &str) -> u64 {
	if let Some(s) = input.strip_prefix("0x") {
        u64::from_str_radix(s, 16).unwrap()
    } else if let Some(s) = input.strip_prefix("0b") {
        u64::from_str_radix(s, 2).unwrap()
    } else {
        input.parse().unwrap()
    }
}
