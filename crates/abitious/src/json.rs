//! A tiny, dependency-free JSON reader — just enough to walk `cargo metadata` output.
//!
//! The dep budget rules out `serde_json` (the shipped reader/stub tree must stay lean and
//! the CLI's only declared deps are the producer + reader). `cargo metadata` emits
//! well-formed UTF-8 JSON, so a compact recursive-descent parser into an order-preserving
//! [`Json`] value is all the `abi` CLI needs to find a package's cdylib target and the
//! workspace `target_directory`. Object member lookup is linear (`Json::get`) — the maps
//! here are tiny.

use std::fmt;

/// A parsed JSON value. Objects keep member order (a `Vec` of pairs, not a map) so the
/// parser carries no `HashMap`/`serde` dependency; the metadata objects are small enough
/// that linear [`Json::get`] lookups are free.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// The value for object member `key`, or `None` if this is not an object / lacks it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// This value as a `&str`, if it is a JSON string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// This value as a slice, if it is a JSON array.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// A parse failure with a human-readable reason and the byte offset it was hit at.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    /// What went wrong.
    pub reason: String,
    /// The byte offset into the input where parsing stopped.
    pub at: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.at, self.reason)
    }
}

impl std::error::Error for ParseError {}

/// Parse a complete JSON document, rejecting trailing non-whitespace bytes.
pub fn parse(input: &str) -> Result<Json, ParseError> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let value = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(p.err("unexpected trailing bytes after the JSON value"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, reason: &str) -> ParseError {
        ParseError {
            reason: reason.to_string(),
            at: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<Json, ParseError> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b't') => self.parse_lit("true", Json::Bool(true)),
            Some(b'f') => self.parse_lit("false", Json::Bool(false)),
            Some(b'n') => self.parse_lit("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            Some(_) => Err(self.err("unexpected character at start of value")),
            None => Err(self.err("unexpected end of input")),
        }
    }

    fn parse_lit(&mut self, lit: &str, value: Json) -> Result<Json, ParseError> {
        if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn parse_object(&mut self) -> Result<Json, ParseError> {
        self.pos += 1; // consume '{'
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected a string key in object"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':' after object key"));
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.parse_value()?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Json, ParseError> {
        self.pos += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.pos += 1; // consume opening '"'
        let mut out = String::new();
        loop {
            let b = self.peek().ok_or_else(|| self.err("unterminated string"))?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.parse_unicode_escape()?),
                        _ => return Err(self.err("invalid escape sequence")),
                    }
                }
                _ => {
                    // Copy one UTF-8 scalar. cargo emits raw UTF-8 in strings; walk the
                    // continuation bytes so multi-byte characters survive intact.
                    let start = self.pos;
                    let len = utf8_len(b);
                    let end = start
                        .checked_add(len)
                        .filter(|&e| e <= self.bytes.len())
                        .ok_or_else(|| self.err("truncated UTF-8 sequence"))?;
                    let s = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| self.err("invalid UTF-8 in string"))?;
                    out.push_str(s);
                    self.pos = end;
                }
            }
        }
    }

    /// Parse the four hex digits of a `\u` escape, combining a UTF-16 surrogate pair when
    /// a high surrogate is immediately followed by `\u<low>`. Falls back to U+FFFD for a
    /// lone/invalid surrogate rather than failing the whole document.
    fn parse_unicode_escape(&mut self) -> Result<char, ParseError> {
        let hi = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&hi) {
            if self.bytes[self.pos..].starts_with(b"\\u") {
                self.pos += 2;
                let lo = self.read_hex4()?;
                if (0xDC00..=0xDFFF).contains(&lo) {
                    let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    return Ok(char::from_u32(c).unwrap_or('\u{FFFD}'));
                }
            }
            return Ok('\u{FFFD}');
        }
        Ok(char::from_u32(hi).unwrap_or('\u{FFFD}'))
    }

    fn read_hex4(&mut self) -> Result<u32, ParseError> {
        let slice = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("truncated \\u escape"))?;
        let mut value = 0u32;
        for &b in slice {
            let digit = (b as char)
                .to_digit(16)
                .ok_or_else(|| self.err("invalid hex digit in \\u escape"))?;
            value = value * 16 + digit;
        }
        self.pos += 4;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            // The full JSON number grammar's byte set: digits, sign, decimal point, exponent.
            if b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("bad number"))?;
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| self.err("malformed number"))
    }
}

/// Encode `s` as a JSON string literal — surrounding quotes plus the escapes a receipt path
/// or an enum name can contain. The write-side twin of the reader above: the dep budget
/// rules out `serde_json`, so `abi`'s receipt (`build`) and report (`inspect`) writers share
/// THIS one hand-rolled encoder rather than each carrying an identical copy. (The separate
/// `abitious-producer` crate keeps its own copy to avoid a cross-crate coupling.)
pub fn encode_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The byte length of a UTF-8 scalar from its leading byte (1..=4).
fn utf8_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead >> 5 == 0b110 {
        2
    } else if lead >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse("true").unwrap(), Json::Bool(true));
        assert_eq!(parse("false").unwrap(), Json::Bool(false));
        assert_eq!(parse("42").unwrap(), Json::Number(42.0));
        assert_eq!(parse("-3.5e2").unwrap(), Json::Number(-350.0));
        assert_eq!(parse("\"hi\"").unwrap(), Json::String("hi".to_string()));
    }

    #[test]
    fn parses_nested_objects_and_arrays_with_whitespace() {
        let v = parse("  { \"a\" : [1, 2, {\"b\": \"c\"}], \"d\": null }  ").unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            v.get("a").unwrap().as_array().unwrap()[2]
                .get("b")
                .unwrap()
                .as_str(),
            Some("c")
        );
        assert_eq!(v.get("d"), Some(&Json::Null));
        assert!(v.get("missing").is_none());
    }

    #[test]
    fn parses_empty_containers() {
        assert_eq!(parse("{}").unwrap(), Json::Object(vec![]));
        assert_eq!(parse("[]").unwrap(), Json::Array(vec![]));
    }

    #[test]
    fn decodes_string_escapes_and_unicode() {
        let v = parse(r#""a\"b\\c\/d\n\t\r\b\fAé""#).unwrap();
        assert_eq!(v.as_str(), Some("a\"b\\c/d\n\t\r\u{0008}\u{000c}Aé"));
    }

    #[test]
    fn decodes_bmp_unicode_escapes() {
        // Literal `\u` escapes in the Basic Multilingual Plane (A = U+0041, é = U+00E9).
        // `bs` is a real backslash from its byte, so `input` is literally `"Aé"`.
        let bs = char::from(92u8);
        let input = format!(r#""{bs}u0041{bs}u00e9""#);
        assert_eq!(parse(&input).unwrap().as_str(), Some("Aé"));
    }

    #[test]
    fn decodes_surrogate_pair_escapes() {
        // U+1F600 GRINNING FACE, written as its UTF-16 surrogate pair escape.
        let bs = char::from(92u8);
        let input = format!(r#""{bs}uD83D{bs}uDE00""#);
        assert_eq!(parse(&input).unwrap().as_str(), Some("😀"));
    }

    #[test]
    fn lone_or_broken_surrogates_become_replacement_char() {
        // A lone high surrogate → U+FFFD.
        assert_eq!(parse(r#""\uD800""#).unwrap().as_str(), Some("\u{FFFD}"));
        // A high surrogate followed by a NON-low-surrogate \u escape → U+FFFD then that char.
        assert_eq!(parse(r#""\uD800A""#).unwrap().as_str(), Some("\u{FFFD}A"));
        // A high surrogate immediately followed by a `\u` escape that PARSES but is NOT a low
        // surrogate (here a second high surrogate, U+D800): the inner low-surrogate range
        // check is false, so the pair fails and collapses to U+FFFD (the second `\u` escape
        // is consumed as the attempted low half). This is the only input that drives the
        // false-branch of the low-surrogate range test — reached only when the `\u` low half
        // parses yet falls outside 0xDC00..=0xDFFF.
        assert_eq!(
            parse(r#""\uD800\uD800""#).unwrap().as_str(),
            Some("\u{FFFD}")
        );
        // A high surrogate followed by a non-escape byte → U+FFFD, then the byte copied.
        assert_eq!(parse(r#""\uD800Z""#).unwrap().as_str(), Some("\u{FFFD}Z"));
    }

    #[test]
    fn rejects_broken_unicode_and_escape_sequences() {
        assert!(parse(r#""\uXYZW""#).is_err()); // non-hex digits
        assert!(parse(r#""\u12""#).is_err()); // truncated (fewer than 4 hex)
        assert!(parse(r#""\q""#).is_err()); // invalid escape letter
        assert!(parse("\"\\").is_err()); // trailing backslash: unterminated escape
    }

    #[test]
    fn rejects_missing_comma_in_array() {
        assert!(parse("[1 2]").is_err());
    }

    #[test]
    fn rejects_an_unterminated_object_key() {
        // The key position sees a `"`, so parse_object calls parse_string — which then hits
        // end-of-input mid-key. The failure propagates through the `let key = parse_string()?`
        // in parse_object (a distinct arm from the "expected a string key" guard, which fires
        // only when the key does NOT start with a quote).
        assert!(parse("{\"abc").is_err());
    }

    #[test]
    fn rejects_bad_hex_in_a_surrogate_low_half() {
        // A high surrogate is immediately followed by a `\u` escape whose four hex digits are
        // invalid: parse_unicode_escape consumes the `\u`, then the low-half read_hex4 fails
        // and the error propagates through `let lo = read_hex4()?` (the low-half arm, distinct
        // from the high-half read_hex4 at the top of the function).
        let bs = char::from(92u8);
        let input = format!(r#""{bs}uD800{bs}uzzzz""#);
        assert!(parse(&input).is_err());
    }

    #[test]
    fn rejects_a_number_that_lexes_but_does_not_parse() {
        // The number scanner accepts the JSON-number byte set greedily, so these all lex into a
        // digit/sign/dot/exp run yet fail `str::parse::<f64>()` — driving the `malformed number`
        // map_err arm rather than any earlier structural guard.
        assert!(parse("-").is_err()); // a lone sign
        assert!(parse("1.2.3").is_err()); // two decimal points
        assert!(parse("9e").is_err()); // exponent with no digits
    }

    #[test]
    fn keeps_raw_utf8_in_strings() {
        // 1-, 2-, and 3-byte raw UTF-8 scalars (é = 2 bytes, em dash = 3 bytes).
        let v = parse("\"café — au lait\"").unwrap();
        assert_eq!(v.as_str(), Some("café — au lait"));
        // A raw 4-byte UTF-8 scalar (😀, U+1F600) exercises utf8_len's 4-byte arm.
        let v = parse("\"go 😀 now\"").unwrap();
        assert_eq!(v.as_str(), Some("go 😀 now"));
    }

    #[test]
    fn as_str_and_as_array_reject_wrong_types() {
        assert!(parse("42").unwrap().as_str().is_none());
        assert!(parse("42").unwrap().as_array().is_none());
        assert!(parse("42").unwrap().get("x").is_none());
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse("").is_err());
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\":}").is_err());
        assert!(parse("{\"a\" 1}").is_err());
        assert!(parse("tru").is_err());
        assert!(parse("\"unterminated").is_err());
        assert!(parse("42 43").is_err()); // trailing bytes
        assert!(parse("{\"a\":1 \"b\":2}").is_err());
    }

    #[test]
    fn parse_error_displays_offset() {
        let e = parse("nul").unwrap_err();
        assert!(e.to_string().contains("invalid JSON at byte"));
    }

    #[test]
    fn encode_string_escapes_every_arm() {
        // The shared encoder now consolidated out of build.rs (`json_string`) and inspect.rs
        // (`json_str`): quote, backslash, newline, carriage return, tab, and the generic
        // control-char `\u` fallback — plus a plain pass-through.
        assert_eq!(encode_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(
            encode_string("q\"b\\c\n\r\t\u{01}"),
            "\"q\\\"b\\\\c\\n\\r\\t\\u0001\""
        );
        assert_eq!(encode_string("plain/path.node"), "\"plain/path.node\"");
    }
}
