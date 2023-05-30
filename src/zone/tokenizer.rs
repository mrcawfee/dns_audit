/**
DNS Audit Tool

(c) 2023 Benjamin P Wilder, All Rights Reserved

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/


#[derive(PartialEq, Eq,Clone)]
pub enum TokenType {
	TypeNone,
	TypeWhite,
	TypeParenSt,
	TypeParenEnd,
	TypeToken,
	TypeNumber,
	TypeString,
	TypeDirective
}
#[derive(Clone)]
pub struct ZoneToken {
	pub token : String,
	pub token_type : TokenType,
	pub line : u32
}

impl ZoneToken {
	pub fn new() -> Self {
		Default::default()
	}

	pub fn to_string(&self) -> String {
		if self.token_type == TokenType::TypeString {
			return format!("\"{}\"", ZoneLines::escape(&self.token));
		}
		return self.token.clone();
	}

	pub fn ignore_white( iter : &mut std::slice::Iter<&ZoneToken> ) -> Result<bool, String> {
		
		loop {
			match iter.next() {
				Some(m) => {
					if m.token_type != TokenType::TypeWhite  {
						return Err( format!("Expected whitespace or empty, got {} at line {} ", m.token, m.line));
					}
				},
				None => { break; }
			};
		};

		Ok(true)
	}

	/**
	 * expect the next token to be a number with type T and return it
	 */
	pub fn expect_int<T: std::fmt::Display + std::str::FromStr >( iter : &mut std::slice::Iter<&ZoneToken> ) -> Result<T, String> {
		match iter.next() {
			Some(tok) => {
				if tok.token_type != TokenType::TypeNumber {
					return Err(format!("expected number for mx weight, got '{}' on line {}", tok.token, tok.line));
				}

				match tok.token.parse::<T>() {
					Ok(t) => { Ok(t) }, 
					Err(_e) => {
						return Err(format!("invalid Number, got '{}' at line {}", tok.token, tok.line ));
					}
				}
		
			},
			None => { return Err("Expected token, got EOL".to_string()); }
		}

	}


	/**
	 * expect the next token to be a number with type T and return it
	 */
	 pub fn expect_non_white( iter : &mut std::slice::Iter<&ZoneToken> ) -> Result<String, String> {
		match iter.next() {
			Some(tok) => {
				if tok.token_type == TokenType::TypeWhite {
					return Err(format!("expected number for mx weight, got '{}' on line {}", tok.token, tok.line));
				}

				Ok(tok.token.clone())
			},
			None => { return Err("Expected token, got EOL".to_string()); }
		}

	}

}

impl Default for ZoneToken {
	fn default() -> Self {
		ZoneToken {
			token: String::new(),
			token_type: TokenType::TypeNone,
			line: 0
		}
	}
}

impl std::fmt::Display for ZoneToken {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let v: String;
		if self.token_type == TokenType::TypeString {
			v = format!("\"{}\"", ZoneLines::escape(&self.token));
		} else { 
			v = self.token.clone(); 
		}
		write!(f, "{}", v)
	}
}

pub struct ZoneLine {
	pub tokens : Vec<ZoneToken>    
}

pub struct ZoneLines {
	pub lines: Vec<ZoneLine>
}

impl ZoneLines {

	/**
	 * create a zone file from the inputted path, returns the ZoneFile struct or an io error
	 * if there was one
	 */
	pub fn create( filename : & String ) -> Result<ZoneLines, String> { 

		let mut rval : ZoneLines =  Default::default();

		let file: std::fs::File = match std::fs::File::open(filename) {
			Ok(m) => { m },
			Err(e) => { return Err(e.to_string()) }
		};

		rval.lines = rval.get_record_tokens( &file )?;

		return Ok(rval);
	}

	/**
	 * Take the zone file and split it up into a vector of the individual record lines, this will also
	 * properly take in the () values as well as split up strings and whitespace
	 * 
	 * RFC-1035
	 *
	 * returns the tokenized zone file, not the records
	 */
	fn get_record_tokens( &self, mut file : &std::fs::File ) -> Result<Vec<ZoneLine>, String> {

		let mut lines : Vec<ZoneLine> = Vec::new();

		let mut is_quote : bool = false;
		let mut paren_ct : i32 = 0;
		let mut skip_endline : bool = false;
		let mut is_white : bool = false;

		const BUFF_LEN : usize = 4096;

		let mut buffer = [0u8; BUFF_LEN];

		let mut line = ZoneLine {
			tokens: Vec::new()
		};

		let mut tok: ZoneToken = ZoneToken::new();
		tok.line = 1;

		let mut line_no: u32 = 1;

		let number_regex : regex::Regex = regex::Regex::new(r"^\d+(\.\d*)?$").unwrap();
		let directive_regex = regex::Regex::new(r"^\$[A-Za-z]+$").unwrap();

		// lambda function to push the tokens and reset everything that needs it
		let push_token = | mut tok : ZoneToken, line : &mut ZoneLine, is_white : &mut bool, line_no : &u32 | -> ZoneToken { 
			if tok.token.len() > 0 {

				// no token type, figure it out
				if tok.token_type == TokenType::TypeNone {

					if number_regex.is_match( &tok.token ) {
						tok.token_type = TokenType::TypeNumber;
					} else if directive_regex.is_match( &tok.token ) {
						tok.token_type = TokenType::TypeDirective;
					} else {
						tok.token_type = TokenType::TypeToken;
					}

				}

				line.tokens.push(tok);
			}
			*is_white = false;
			return ZoneToken {
				token: String::new(),
				token_type: TokenType::TypeNone,
				line: line_no.clone()
			};
		};

		let mut push_line= | line : ZoneLine | -> ZoneLine { 
			lines.push( line );
			return ZoneLine { tokens: Vec::new() };
		};

		loop {
			use std::io::Read;
			let read_count = match file.read(&mut buffer[..]) {
				Ok(x) => { x },
				Err( e ) => { 
					let msg = e.to_string();
					return Err(msg);
				 }
			};

			let mut idx: usize = 0;
			while idx < read_count {

				if buffer[idx] == '\n' as u8 {
					line_no += 1;
				}
				
				if is_quote {

					// flag set for us being within a string, process the end of the string

					if idx < read_count - 1 && buffer[idx] == '\\' as u8 && buffer[idx+1] == '"' as u8 {
						// escape sequence for a quote inside the thingie
						tok.token.push(buffer[ idx ] as char);
						tok.token.push(buffer[ idx + 1] as char);
						idx += 2;
						continue;
					} else if buffer[idx] == '\"' as u8 {
						tok.token = ZoneLines::unescape(&tok.token);
						tok = push_token(tok,&mut line, &mut is_white, &line_no);
						is_quote = false;
					} else {
						tok.token.push(buffer[idx] as char );
					}
				} else if skip_endline {
					// skipping until the end of the line, this is for comments in the file which we are stripping
					// out
					if buffer[idx] == '\n' as u8 {
						skip_endline = false;
					}
				} else {

					// other characters

					let c: char =  buffer[idx] as char;
					match c {
						';' => {
							// comment start
							skip_endline = true;
							tok = push_token(tok,&mut line, &mut is_white, &line_no);
						},
						'(' => {
							if !is_white {
								tok = push_token(tok,&mut line, &mut is_white, &line_no);
							}

							paren_ct += 1;
						},
						')' => {
							if paren_ct == 0  {
								let msg = format!("unmatched ) at line {line_no}");
								return Err(  msg );
							}
							if !is_white {
								tok = push_token(tok,&mut line, &mut is_white, &line_no);
							}
							paren_ct -= 1;
						},
						'\"' => {

							tok = push_token(tok,&mut line, &mut is_white, &line_no);

							tok.token_type = TokenType::TypeString;
							is_quote = true;
						},
						'\n' => {
							if paren_ct == 0 {
								tok = push_token(tok,&mut line, &mut is_white, &line_no);
								line = push_line(line);
							} else {
								if is_white {
									tok.token.push(c);
								} else {
									tok = push_token(tok, &mut line, &mut is_white, &line_no);
									tok.token_type = TokenType::TypeWhite;
									tok.token.push(c);
									is_white = true;
								}
							}
						},
						'\r' | ' '  | '\t' => {
							if is_white {
								tok.token.push(c);
							} else {
								tok = push_token(tok, &mut line, &mut is_white, &line_no);
								tok.token_type = TokenType::TypeWhite;
								tok.token.push(c);
								is_white = true;
							}
						},
						_ => {
							if is_white { 
								tok = push_token(tok, &mut line, &mut is_white, &line_no);
							}
							tok.token.push( c );
						}
					}
				}


				idx+=1;
			}

			if read_count != BUFF_LEN {
				break;
			}
		}

		if tok.token.len() > 0  {
			push_token(tok, &mut line, &mut is_white, &line_no);           
		}

		if line.tokens.len() > 0  {
			push_line(line);
		}

		return Ok(lines);
	}

	/**
	 * unescape strings 
	 */
	pub fn unescape( in_str : & String ) -> String {
		let mut rval = String::new();

		let mut chars = in_str.chars();

		loop {

			let c = match chars.next() {
				Some(n) => { n },
				None => { break; }
			};

			if c == '\\' {

				match chars.next() {
					Some(m) => {

						// this is a dumb way to do this, but this is for the \XXX escaping
						// of characters
						if m >= '0' && m <= '9' {
							
							let m2 = match chars.next() {
								Some(n) => { n },
								None => { 
									rval.push(m);
									break;
								}
							};

							let m3 = match chars.next() {
								Some(n) => { n },
								None => { 
									rval.push(m);
									rval.push(m2);
									break;
								}
							};

							if m2 >= '0' && m2 <= '9' && m3 >= '0' && m3 <= '9'  {
								let mut s = String::new();
								s.push(m);
								s.push(m2);
								s.push(m3);

								// convert to number
								match s.parse::<u8>() {
									Ok(t) => {
										rval.push( t as char );
									}, 
									Err(_e) => {
										rval.push(m);
										rval.push(m2);
										rval.push(m3);
									}
								}

							}

						} else {
							rval.push(m);
						}
					},
					None => {
						rval.push(c);
						break;
					}
				}

			} else {
				rval.push(c);
			}
		}

		return rval;
	}

	/**
	 * escape quotes and non-printable ascii characters
	 */
	pub fn escape( in_str : & String ) -> String {
		let mut rval = String::new();

		let mut chars = in_str.chars();

		loop {

			let c = match chars.next() {
				Some(n) => { n },
				None => { break; }
			};

			if c == '"' {
				rval.push('\\');
				rval.push(c);
			} else if (c as u8) < 0x20 || (c as u8) >= 0x7f {
				rval += &format!("\\{:03}", (c as u8) );
			} else {
				rval.push(c);
			}
		};

		return rval;
	}

}

impl Default for ZoneLines {
	fn default() -> Self {
		ZoneLines {
			lines: Vec::new()
		}
	}
}

impl std::fmt::Display for TokenType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", match &self {
			TokenType::TypeNone => { "TypeNone" },
			TokenType::TypeWhite => { "TypeWhite" },
			TokenType::TypeParenSt => { "TypeParenSt" },
			TokenType::TypeParenEnd => { "TypeParenEnd" },
			TokenType::TypeToken => { "TypeToken" },
			TokenType::TypeNumber => { "TypeNumber" },
			TokenType::TypeString => { "TypeString" },
			TokenType::TypeDirective => { "TypeDirective" }
		})
	}
}