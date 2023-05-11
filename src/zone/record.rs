/**
 * Zone records 
 */

use super::tokenizer;

struct RecordName {
	pub name: String,
	pub fqdn: String,
}

pub struct ZoneRecord {
	pub name : RecordName,
	pub ttl : u32,
	pub class : String,
	pub rdata: Vec<tokenizer::ZoneToken>
}	

#[derive(PartialEq, Eq)]
enum RecordPos {
	DN,
	TTL,
	IN,
	RDATA
}


impl ZoneRecord {

	pub fn create( line : & tokenizer::ZoneLine ) -> Result<Self, String> {

		let mut record: ZoneRecord = Default::default();

		let mut line_iter = line.tokens.iter();

		let mut rec_pos = RecordPos::DN;

		loop {
			let tok = match line_iter.next() {
				None => { break; }
				Some(a) => { a }
			};

			if rec_pos == RecordPos::DN {

				if tok.token_type != tokenizer::TokenType::TypeWhite {
					record.name.name = tok.token;
				}
				rec_pos = RecordPos::TTL;
			} else if rec_pos == RecordPos::TTL {
				match tok.token.parse::<u32>() {
					Ok(t) => {
						record.ttl = t;
						rec_pos = RecordPos::IN;
					}, 
					Err(e) => {
						if 
							tok.token.to_ascii_uppercase() == "IN" ||
							tok.token.to_ascii_uppercase() == "CS" ||
							tok.token.to_ascii_uppercase() == "CH" ||
							tok.token.to_ascii_uppercase() == "HS"
						{
							record.class = tok.token;
						} else {
							return Err(e.to_string());
						}
					}
				}
			}

		};


		return Ok(record);
	}

}

impl Default for ZoneRecord {

	fn default() -> Self {
		ZoneRecord {
			name: RecordName{ 
				name: String::new(),
				fqdn: String::new()
			},
			ttl : 0,
			class: String::new(),
			rdata : Vec::new()
		}
	}

}
