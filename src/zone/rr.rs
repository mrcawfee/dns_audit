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

use base64::Engine;

use super::{tokenizer, record};


pub trait RecordRDATA : std::fmt::Display {

	/** process the ORIGIN function for me */
	fn origin( &mut self, origin : &String );

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any;

	fn as_any( &self ) -> &dyn std::any::Any;

	fn clone_box (&self) -> Box<dyn RecordRDATA>;
	
	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result<(), String>;

	fn from_wire( &mut self, size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String>;

}


/**
 * A Records
 */
pub struct RDATAa {
	pub ip : std::net::Ipv4Addr
}

impl Default for RDATAa {
	fn default() -> Self {
		Self {
			ip: std::net::Ipv4Addr::new(0,0,0,0)
		}
	}
}

impl RecordRDATA for RDATAa { 

	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result<(), String> {

		let mut iter = tokens.iter();

		let tok = match iter.next() {
			Some(m) => { m },
			None => { return Err("Expected token, got EOL".to_string()); }
		} ;

		use std::str::FromStr;

		match std::net::Ipv4Addr::from_str( &tok.token ) {
			Ok(m) => { self.ip = m; },
			Err(e) => { return Err(e.to_string()); }
		};

		loop {
			match iter.next() {
				Some(m) => {
					if m.token_type != tokenizer::TokenType::TypeWhite  {
						return Err( format!("Expected whitespace or empty, got {} at line {} ", m.token, m.line));
					}
				},
				None => { break; }
			};
		};

		Ok(())
		
	}

	fn origin( &mut self, _origin : &String ) { }

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}

	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}

	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new(self.clone())
	}

	fn from_wire( &mut self, size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {

		assert_eq!( std::mem::size_of::<u32>(), size as usize );
		self.ip = std::net::Ipv4Addr::from(crate::query::dns_read_int!(u32, buff, offset));

		Ok(())
    }

}

impl Clone for RDATAa {

	fn clone(&self) -> Self {
		Self {
			ip : self.ip.clone()
		}
	}

}

impl std::fmt::Display for RDATAa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip.to_string())
    }
}


/**
 * AAAA Records
 */
pub struct RDATAaaaa {
	pub ip : std::net::Ipv6Addr
}

impl Default for RDATAaaaa {
	fn default() -> Self {
		Self {
			ip: std::net::Ipv6Addr::new(0,0,0,0,0,0,0,0 )
		}
	}
}

impl RecordRDATA for RDATAaaaa { 

	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result< (), String> {

		let mut iter: std::slice::Iter<&tokenizer::ZoneToken> = tokens.iter();

		let tok = match iter.next() {
			Some(m) => { m },
			None => { return Err("Expected token, got EOL".to_string()); }
		} ;

		use std::str::FromStr;

		match std::net::Ipv6Addr::from_str( &tok.token ) {
			Ok(m) => { self.ip = m; },
			Err(e) => { return Err(e.to_string()); }
		};

		match tokenizer::ZoneToken::ignore_white(&mut iter) {
			Ok(_m) => {},
			Err(e) => { return Err(e);}
		}

		Ok(())
		
	}


	fn origin( &mut self, _origin : &String ) { }

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}
	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}
	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new(self.clone())
	}

	fn from_wire( &mut self, size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {
		assert_eq!( std::mem::size_of::<u128>(), size as usize );
        self.ip = std::net::Ipv6Addr::from( crate::query::dns_read_int!(u128, buff, offset));
		Ok(())
    }

}


impl Clone for RDATAaaaa { 
	fn clone(&self) -> Self {
		Self {
			ip : self.ip.clone()
		}
	}
}


impl std::fmt::Display for RDATAaaaa { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.ip.to_string())
	}
}

/**
 * Generic record that we do not know what it is
 */
pub struct RDATAgeneric {
	pub tokens : Vec<tokenizer::ZoneToken>,
	pub wire_data : Vec<u8>
}

impl Default for RDATAgeneric {
	fn default() -> Self {
		Self {
			tokens : Vec::new(),
			wire_data : Vec::new()
		}
	}
}

impl RecordRDATA for RDATAgeneric {

	fn from_tokens( &mut self, tokens : & Vec<&tokenizer::ZoneToken> ) -> Result<(), String> {

		for tok in tokens {
			self.tokens.push( tok.clone().clone() );
		}

		return Ok(());
	}

	fn origin( &mut self, _origin : &String ) { }

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}
	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}
	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new(self.clone())
	}

	fn from_wire( &mut self, size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {
		self.wire_data = crate::query::read_buff(buff, offset, size as usize );
		Ok(())
	}

}


impl Clone for RDATAgeneric { 
	fn clone(&self) -> Self {
		Self {
			tokens : self.tokens.clone(),
			wire_data : self.wire_data.clone()
		}
	}
}

impl std::fmt::Display for RDATAgeneric {

	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

		for tok in &self.tokens {
			if tok.token_type == tokenizer::TokenType::TypeString {
				write!(f, "\"{}\" ", tokenizer::ZoneLines::escape(&tok.token))?;
			} else {
				write!(f, "{} ", tok.token)?;
			}
		}

        write!(f, " ; Generic")
    }

}


/**
 * CNAME,DNAME,NS Records
 */
pub struct RDATANameRR {
	pub name : record::RecordName
}

impl Default for RDATANameRR {
	fn default() -> Self {
		Self {
			name : Default::default()
		}
	}
}

impl RecordRDATA for RDATANameRR { 

	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result< (), String> {

		let mut iter: std::slice::Iter<&tokenizer::ZoneToken> = tokens.iter();

		match iter.next() {
			Some(m) => { self.name = record::RecordName::new(&m.token) },
			None => { return Err("Expected token, got EOL".to_string()); }
		} ;

		match tokenizer::ZoneToken::ignore_white(&mut iter) {
			Ok(_m) => {},
			Err(e) => { return Err(e);}
		}

		Ok(())
	}

	fn origin( &mut self, origin : &String ) { 
		self.name.origin(origin);
	}

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}
	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}
	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new(self.clone())
	}


	fn from_wire( &mut self, _size : u16,  buff : &[u8], offset : &mut usize ) -> Result<(), String> {
		self.name.name = crate::query::read_qname(buff, offset).as_str().to_string();
		if !self.name.name.ends_with(&".".to_string()) {
			self.name.name.push('.');
		}
		self.name.fqdn = self.name.name.clone();
		Ok(())
	}



}

impl Clone for RDATANameRR { 
	fn clone(&self) -> Self {
		Self {
			name : self.name.clone()
		}
	}
}

impl std::fmt::Display for RDATANameRR { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.name.to_string())
	}
}



/**
 * MX Records
 */
pub struct RDATAmx {
	pub weight : u16,
	pub target : record::RecordName
}

impl Default for RDATAmx {
	fn default() -> Self {
		Self {
			weight :0,
			target : Default::default()
		}
	}
}

impl RecordRDATA for RDATAmx { 

	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result< (), String> {

		let mut iter: std::slice::Iter<&tokenizer::ZoneToken> = tokens.iter();

		let mut tok = match iter.next() {
			Some(m) => { m },
			None => { return Err("Expected token, got EOL".to_string()); }
		} ;

		if tok.token_type != tokenizer::TokenType::TypeNumber {
			return Err(format!("expected number for mx weight, got '{}' on line {}", tok.token, tok.line));
		}

		let weight : u16 = match tok.token.parse::<u16>() {
			Ok(t) => { t }, 
			Err(e) => {
				return Err(format!("invalid TTL, got '{}' at line {} ({e}) ", tok.token, tok.line));
			}
		};

		tok = match iter.next() {
			Some(m) => { m },
			None => { return Err("Expected token, got EOL".to_string()); }
		} ;

		
		self.target = record::RecordName::new(&tok.token);
		self.weight = weight;

		match tokenizer::ZoneToken::ignore_white(&mut iter) {
			Ok(_m) => {},
			Err(e) => { return Err(e);}
		}

		Ok(())
		
	}


	fn origin( &mut self, origin : &String ) { 
		self.target.origin(origin);
	}

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}
	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}
	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new( self.clone() )
	}

	fn from_wire( &mut self, _size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {
        self.weight = crate::query::dns_read_int!(u16, buff, offset);
		self.target.name = crate::query::read_qname(buff,offset).to_string();
		self.target.fqdn = self.target.name.clone();
		Ok(())
    }

}

impl Clone for RDATAmx { 
	fn clone(&self) -> Self {
		Self {
			weight: self.weight,
			target: self.target.clone()
		}
	}
}

impl std::fmt::Display for RDATAmx { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}\t{}", self.weight, self.target.to_string())
	}
}

/**
 * DS Records
 * 
 * RFC-3658
 */
pub struct RDATAds {
	pub key_tag : u16,
	pub algorithm : u8,
	pub digest_type: u8,
	pub digest : Vec<u8>
}


impl Default for RDATAds {
	fn default() -> Self {
		Self {
			key_tag: 0,
			algorithm: 0,
			digest_type: 0,
			digest: Vec::new()
		}
	}
}

impl RecordRDATA for RDATAds { 

	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result< (), String> {

		let mut iter: std::slice::Iter<&tokenizer::ZoneToken> = tokens.iter();

		self.key_tag = tokenizer::ZoneToken::expect_int::<u16>(&mut iter)?;
		self.algorithm = tokenizer::ZoneToken::expect_int::<u8>(&mut iter)?;
		self.digest_type = tokenizer::ZoneToken::expect_int::<u8>(&mut iter)?;

		let mut digest = String::new();
		loop {
			match iter.next() {
				Some(tok) => {
					digest.push_str( &tok.token );
				},
				None => {
					break;
				}
			}
		}

		self.digest = base64::engine::general_purpose::STANDARD.decode(digest).unwrap();

		Ok(())
	}

	fn origin( &mut self, _origin : &String ) { }

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}
	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}
	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new(self.clone())
	}

	fn from_wire( &mut self, size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {
		let start_offset : usize = offset.clone();
        self.key_tag = crate::query::dns_read_int!(u16, buff, offset);
		self.algorithm = crate::query::dns_read_int!(u8, buff, offset);
		self.digest_type = crate::query::dns_read_int!(u8, buff, offset);
		self.digest = crate::query::read_buff(buff, offset, size as usize - (*offset - start_offset));

		Ok(())
    }



}

impl Clone for RDATAds { 
	fn clone(&self) -> Self {
		Self {
			key_tag: self.key_tag,
			algorithm: self.algorithm,
			digest_type: self.digest_type,
			digest: self.digest.clone()
		}
	}
}


impl std::fmt::Display for RDATAds { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

		let encoded: String = base64::engine::general_purpose::STANDARD.encode(self.digest.clone());

		write!(f, "{}\t{}\t{}\t{}", self.key_tag, self.algorithm, self.digest_type, encoded)
	}
}


/**
 * TXT Records
 */
pub struct RDATAtxt {
	pub value : String
}

impl Default for RDATAtxt {
	fn default() -> Self {
		Self {
			value: String::new()
		}
	}
}


impl RecordRDATA for RDATAtxt { 
	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result< (), String> {

		self.value.clear();

		for tok in tokens {
			self.value.push_str( &tok.token );
		}

		Ok(())

	}


	fn origin( &mut self, _origin : &String ) { }

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}
	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}
	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new(self.clone())
	}

	fn from_wire( &mut self, size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {
        let value = crate::query::read_buff(buff, offset, size as usize);
		self.value = String::with_capacity( size as usize );
		for c in value {
			self.value.push(c as char);
		}
		Ok(())
    }

}

impl Clone for RDATAtxt { 
	fn clone(&self) -> Self {
		Self {
			value : self.value.clone()
		}
	}
}

impl std::fmt::Display for RDATAtxt { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

		if self.value.len() > 255 {

			write!(f, "(\n")?;

			let mut x : usize = 0;
			let max_sz : usize = 255;
			while x < self.value.len() {
				let s :&str;
				if x + max_sz < self.value.len() {
					s = &self.value[x..(x+max_sz)];
				} else {
					s = &self.value[x..];
				}
				
				write!(f, "\t\"{}\"\n", tokenizer::ZoneLines::escape( &s.to_string() ))?;
				x += max_sz;
			}

			write!(f, ")")

		} else {
			write!(f, "\"{}\"", tokenizer::ZoneLines::escape( &self.value ))
		}

	}
}


/**
 * SOA Records
 */
pub struct RDATAsoa {
	pub mname : record::RecordName,
	pub rname : record::RecordName,
	pub serial : u32,
	pub refresh : u32,
	pub retry : u32,
	pub expire : u32,
	pub min : u32
}

impl Default for RDATAsoa {
	fn default() -> Self {
		Self {
			mname: Default::default(),
			rname: Default::default(),
			serial: 0,
			refresh: 0,
			retry: 0,
			expire: 0,
			min: 0
		}
	}
}

impl RecordRDATA for RDATAsoa { 

	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result<(), String> {

		let mut iter = tokens.iter();

		self.mname.name = tokenizer::ZoneToken::expect_non_white(&mut iter)?;
		self.rname.name = tokenizer::ZoneToken::expect_non_white(&mut iter)?;
		self.serial = tokenizer::ZoneToken::expect_int::<u32>(&mut iter)?;
		self.refresh = tokenizer::ZoneToken::expect_int::<u32>(&mut iter)?;
		self.retry = tokenizer::ZoneToken::expect_int::<u32>(&mut iter)?;
		self.expire = tokenizer::ZoneToken::expect_int::<u32>(&mut iter)?;
		self.min = tokenizer::ZoneToken::expect_int::<u32>(&mut iter)?;
		
		Ok(())

	}

	fn origin( &mut self, origin : &String ) { 
		self.mname.origin(origin);
		self.rname.origin(origin);
	}

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}
	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}
	fn clone_box(&self) -> Box<dyn RecordRDATA> {
		Box::new( self.clone() )
	}

	fn from_wire( &mut self, _size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {
        
		self.mname.name = crate::query::read_qname(buff, offset).to_string();
		self.mname.fqdn = self.mname.name.clone();

		self.rname.name = crate::query::read_qname(buff, offset).to_string();
		self.rname.fqdn = self.mname.name.clone();

		self.serial = crate::query::dns_read_int!(u32, buff, offset );
		self.refresh = crate::query::dns_read_int!(u32, buff, offset );
		self.retry = crate::query::dns_read_int!(u32, buff, offset );
		self.expire = crate::query::dns_read_int!(u32, buff, offset );
		self.min = crate::query::dns_read_int!(u32, buff, offset );

		Ok(())
    }



}

impl Clone for RDATAsoa { 
	fn clone(&self) -> Self {
		Self {
			mname: self.mname.clone(),
			rname: self.rname.clone(),
			serial: self.serial,
			refresh: self.refresh,
			retry: self.retry,
			expire: self.expire,
			min: self.min
		}
	}
}

impl std::fmt::Display for RDATAsoa { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

		write!(f, "{} {} {} {} {} {} {} ", self.mname, self.rname, self.serial, self.refresh, self.retry, self.expire, self.min)

	}
}

/**
 * RDATAdnskey Records
 */
pub struct RDATAdnskey {
	pub flags : u16,
	pub protocol : u8,
	pub algorithm : u8,
	pub public_key : Vec<u8>
}

impl Default for RDATAdnskey {
	fn default() -> Self {
		Self {
			flags: 0,
			protocol: 0,
			algorithm: 0,
			public_key: Vec::new()
		}
	}
}

impl RecordRDATA for RDATAdnskey { 

	fn from_tokens( &mut self, tokens : &Vec<&tokenizer::ZoneToken> ) -> Result<(), String> {

		let mut iter = tokens.iter();

		self.flags = tokenizer::ZoneToken::expect_int::<u16>(&mut iter)?;
		self.protocol = tokenizer::ZoneToken::expect_int::<u8>(&mut iter)?;
		self.algorithm = tokenizer::ZoneToken::expect_int::<u8>(&mut iter)?; 

		let mut public_key =  String::new();
		

		loop {
			match iter.next() {
				Some(m) =>{ 
					if m.token_type != tokenizer::TokenType::TypeWhite {
						public_key.push_str(&m.token);
						
					}
				}
				None => { break ; }
			}
		};

		self.public_key = base64::engine::general_purpose::STANDARD.decode(public_key).unwrap();

		Ok(())

	}


	fn origin( &mut self, _origin : &String ) { }

	fn as_any_mut( &mut self ) -> &mut dyn std::any::Any {
		self
	}

	fn as_any( &self ) -> &dyn std::any::Any {
		self
	}

	fn clone_box (&self) -> Box<dyn RecordRDATA> {
		Box::new( self.clone() )
    }

	fn from_wire( &mut self, size : u16, buff : &[u8], offset : &mut usize ) -> Result<(), String> {
		let offset_start = offset.clone();
        self.flags = crate::query::dns_read_int!(u16, buff, offset);
		self.protocol = crate::query::dns_read_int!(u8, buff, offset);
		self.algorithm = crate::query::dns_read_int!(u8, buff, offset);
		self.public_key = crate::query::read_buff(buff, offset, size as usize  - (*offset - offset_start));
		Ok(())
    }

}

impl Clone for RDATAdnskey { 
	fn clone(&self) -> Self {
		Self{
			flags: self.flags,
			protocol: self.protocol,
			algorithm: self.algorithm,
			public_key: self.public_key.clone(),
		}
	}
}

impl std::fmt::Display for RDATAdnskey { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

		let encoded: String = base64::engine::general_purpose::STANDARD.encode(self.public_key.clone());

		write!(f, "{} {} {} {} ", self.flags, self.protocol, self.algorithm, encoded)

	}
}


pub fn create_from_type( record_type : record::RecordType ) -> Box<dyn RecordRDATA> {
	
	match record_type {
		record::RecordType::A => {
			Box::new(RDATAa{ ..Default::default() })
		},
		record::RecordType::AAAA => {
			Box::new(RDATAaaaa{ ..Default::default() })
		},
		record::RecordType::CNAME => {
			Box::new(RDATANameRR{ ..Default::default() })
		},
		record::RecordType::DNAME => {
			Box::new(RDATANameRR{ ..Default::default() })
		},
		record::RecordType::MX => {
			Box::new(RDATAmx{ ..Default::default() })
		},
		record::RecordType::NS => {
			Box::new(RDATANameRR{ ..Default::default() })
		},	
		record::RecordType::TXT => {
			Box::new(RDATAtxt{ ..Default::default() })
		},
		record::RecordType::SOA => {
			Box::new(RDATAsoa{ ..Default::default() })
		},
		record::RecordType::DNSKEY => {
			Box::new(RDATAdnskey{ ..Default::default() })
		},
		record::RecordType::DS => {
			Box::new(RDATAds{ ..Default::default() })
		},
		_ => {
			Box::new(RDATAgeneric{ ..Default::default() })
		}
	}
}
