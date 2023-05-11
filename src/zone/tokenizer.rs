/**
 * DNS Record auding tool, zone file parser
 * 
 * @author Ben Wilder
 */

#[derive(PartialEq, Eq)]
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
pub struct ZoneToken {
	pub token : String,
	pub token_type : TokenType
}

impl ZoneToken {
	pub fn new() -> Self {
		Default::default()
	}
}

impl Default for ZoneToken {
	fn default() -> Self {
		ZoneToken {
			token: String::new(),
			token_type: TokenType::TypeNone
		}
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

		let mut line_no = 1;

		let number_regex : regex::Regex = regex::Regex::new(r"^\d+(\.\d*)?$").unwrap();
		let directive_regex = regex::Regex::new(r"^\$[A-Za-z]+$").unwrap();

		// lambda function to push the tokens and reset everything that needs it
		let mut push_token = | mut tok : ZoneToken, line : &mut ZoneLine, is_white : &mut bool | -> ZoneToken { 
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
				token_type: TokenType::TypeNone
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
						tok = push_token(tok,&mut line, &mut is_white);
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
							tok = push_token(tok,&mut line, &mut is_white);
						},
						'(' => {
							tok = push_token(tok,&mut line, &mut is_white);
							line.tokens.push(tok);
							tok = push_token(
								ZoneToken{
									token: "(".to_string(),
									token_type: TokenType::TypeParenSt 
								},
								&mut line, 
								&mut is_white
							);
							paren_ct += 1;
						},
						')' => {
							if paren_ct == 0  {
								let msg = format!("unmatched ) at line {line_no}");
								return Err(  msg );
							}
							tok = push_token(tok,&mut line, &mut is_white);
							tok = push_token(
								ZoneToken{
									token: ")".to_string(),
									token_type: TokenType::TypeParenEnd
								},
								&mut line, 
								&mut is_white
							);
							paren_ct -= 1;
						},
						'\"' => {

							tok = push_token(tok,&mut line, &mut is_white);

							tok.token_type = TokenType::TypeString;
							is_quote = true;
						},
						'\n' => {
							if paren_ct == 0 {
								tok = push_token(tok,&mut line, &mut is_white);
								line = push_line(line);
							} else {
								if is_white {
									tok.token.push(c);
								} else {
									tok = push_token(tok, &mut line, &mut is_white);
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
								tok = push_token(tok, &mut line, &mut is_white);
								tok.token_type = TokenType::TypeWhite;
								tok.token.push(c);
								is_white = true;
							}
						},
						_ => {
							if is_white { 
								tok = push_token(tok, &mut line, &mut is_white);
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
			push_token(tok, &mut line, &mut is_white);           
		}

		if line.tokens.len() > 0  {
			push_line(line);
		}

		return Ok(lines);
	}

	fn unescape( in_str : & String ) -> String {
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
						rval.push(m);
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

}

impl Default for ZoneLines {
	fn default() -> Self {
		ZoneLines {
			lines: Vec::new()
		}
	}
}
