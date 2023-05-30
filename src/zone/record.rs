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

use crate::config::println_verbose;

/**
 * Zone records 
 */

use super::{tokenizer, rr};

use super::super::query;

/**
 * Enumeration containing the record types
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum RecordType {
	A = 1 ,
	AAAA = 28 ,
	AFSDB = 18,
	APL = 42,
	CAA = 257,
	CDNSKEY = 60,
	CDS = 59,
	CERT = 37,
	CNAME = 5,
	CSYNC = 62,
	DHCID = 49,
	DLV = 32769,
	DNAME = 39,
	DNSKEY = 48,
	DS = 43,
	EUI48 = 108,
	EUI64 = 109,
	HINFO = 13,
	HIP = 55,
	HTTPS = 65,
	IPSECKEY = 45,
	KEY = 25,
	KX = 36,
	LOC = 29,
	MX = 15,
	NAPTR = 35,
	NS = 2, 
	NSEC = 47,
	NSEC3 = 50,
	NSEC3PARAM = 51,
	OPENPGPKEY = 61,
	PTR = 12,
	RRSIG = 46,
	RP = 17,
	SIG = 24,
	SMIMEA = 53,
	SOA = 6,
	SRV = 33,
	SSHFP = 44,
	SVCB = 64,
	TA = 32768,
	TKEY = 249,
	TLSA = 52,
	TSIG = 250,
	TXT = 16,
	URI = 256,
	ZONEMD = 63,
	RecordTypeOther = 0,
	Directive = -1
}

impl RecordType {

	pub fn from_u16( indata : &u16 ) -> Self {
		match indata {
			1 => { Self::A },
			28 => { Self::AAAA },
			18 => { Self::AFSDB },
			42 => { Self::APL },
			257 => { Self::CAA },
			60 => { Self::CDNSKEY },
			59 => { Self::CDS },
			37 => { Self::CERT },
			5 => { Self::CNAME },
			62 => { Self::CSYNC },
			49 => { Self::DHCID },
			32769 => { Self::DLV },
			39 => { Self::DNAME },
			48 => { Self::DNSKEY },
			43 => { Self::DS },
			108 => { Self::EUI48 },
			109 => { Self::EUI64 },
			13 => { Self::HINFO },
			55 => { Self::HIP },
			65 => { Self::HTTPS },
			45 => { Self::IPSECKEY },
			25 => { Self::KEY },
			36 => { Self::KX },
			29 => { Self::LOC },
			15 => { Self::MX },
			35 => { Self::NAPTR },
			2 => { Self::NS }, 
			47 => { Self::NSEC },
			50 => { Self::NSEC3 },
			51 => { Self::NSEC3PARAM },
			61 => { Self::OPENPGPKEY },
			12 => { Self::PTR },
			46 => { Self::RRSIG },
			17 => { Self::RP },
			24 => { Self::SIG },
			53 => { Self::SMIMEA },
			6 => { Self::SOA },
			33 => { Self::SRV },
			44 => { Self::SSHFP },
			64 => { Self::SVCB },
			32768 => { Self::TA },
			249 => { Self::TKEY },
			52 => { Self::TLSA },
			250 => { Self::TSIG },
			16 => { Self::TXT },
			256 => { Self::URI },
			63 => { Self::ZONEMD },
			_ => { Self::RecordTypeOther }
		}
	}

}

pub struct RecordName {
	pub name: String,
	pub fqdn: String,
}

impl RecordName {
	pub fn new( dn : &String ) -> Self {
		let mut r = RecordName{ 
			name: dn.clone(),
			fqdn: String::new()
		};

		if dn.ends_with(".") {
			r.fqdn = dn.clone();
		}

		return r;
	}

	pub fn origin ( &mut self, origin : &String ) {
		if self.fqdn.len() == 0{
			
			if self.name == "@" {
				self.fqdn = origin.clone();
			} else if !self.name.ends_with(".") {

				self.fqdn = self.name.clone();
				if !self.fqdn.starts_with(".") {
					self.fqdn.push('.');
				}
				self.fqdn += origin;
			} else {
				self.fqdn = self.name.clone();
			}

		}

	}
}

impl std::fmt::Display for RecordName { 
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.fqdn.len() > 0 {
			write!(f, "{}", self.fqdn)
		} else {
			write!(f, "{}", self.name)
		}
	}
}

impl Clone for RecordName {

	fn clone(&self) -> Self {
		Self {
			name: self.name.clone(),
			fqdn: self.fqdn.clone(),
		}
	}
}


impl Default for RecordName {
	fn default() -> Self {
		RecordName{ 
			name: String::new(),
			fqdn: String::new()
		}
	}
}


pub trait IZoneRecord : std::fmt::Display {

	fn from_iter( &mut self, iter : &mut std::slice::Iter<tokenizer::ZoneToken> ) -> Result<(), String>;

    fn as_any(&mut self) -> &mut dyn std::any::Any;


}

/**
 * Base struct for zone records, real data is in the RDATA value
 */
pub struct ZoneRecord {
	pub name : RecordName,
	pub ttl : i32,
	pub class : query::NSClass,
	pub record_type : RecordType,
	pub record_type_other : Option<String>,
	pub rdata : Option<Box<dyn rr::RecordRDATA>>
}


#[derive(PartialEq, Eq)]
enum RecordPos {
	//DN,
	TTL,
	IN,
	RTYPE,
	RDATA
}

impl RecordType {

	fn from_string ( instr : & str )  -> RecordType {

		match instr.to_ascii_uppercase().as_str() {
			"A" => { RecordType::A },
			"AAAA" => { RecordType::AAAA },
			"AFSDB" => { RecordType::AFSDB },
			"APL" => { RecordType::APL },
			"CAA" => { RecordType::CAA },
			"CDNSKEY" => { RecordType::CDNSKEY },
			"CDS" => { RecordType::CDS },
			"CERT" => { RecordType::CERT },
			"CNAME" => { RecordType::CNAME },
			"CSYNC" => { RecordType::CSYNC },
			"DHCID" => { RecordType::DHCID },
			"DLV" => { RecordType::DLV },
			"DNAME" => { RecordType::DNAME },
			"DNSKEY" => { RecordType::DNSKEY },
			"DS" => { RecordType::DS },
			"EUI48" => { RecordType::EUI48 },
			"EUI64" => { RecordType::EUI64 },
			"HINFO" => { RecordType::HINFO },
			"HIP" => { RecordType::HIP },
			"HTTPS" => { RecordType::HTTPS },
			"IPSECKEY" => { RecordType::IPSECKEY },
			"KEY" => { RecordType::KEY },
			"KX" => { RecordType::KX },
			"LOC" => { RecordType::LOC },
			"MX" => { RecordType::MX },
			"NAPTR" => { RecordType::NAPTR },
			"NS" => { RecordType::NS }, 
			"NSEC" => { RecordType::NSEC },
			"NSEC3" => { RecordType::NSEC3 },
			"NSEC3PARAM" => { RecordType::NSEC3PARAM },
			"OPENPGPKEY" => { RecordType::OPENPGPKEY },
			"PTR" => { RecordType::PTR },
			"RRSIG" => { RecordType::RRSIG },
			"RP" => { RecordType::RP },
			"SIG" => { RecordType::SIG },
			"SMIMEA" => { RecordType::SMIMEA },
			"SOA" => { RecordType::SOA },
			"SRV" => { RecordType::SRV },
			"SSHFP" => { RecordType::SSHFP },
			"SVCB" => { RecordType::SVCB },
			"TA" => { RecordType::TA },
			"TKEY" => { RecordType::TKEY },
			"TLSA" => { RecordType::TLSA },
			"TSIG" => { RecordType::TSIG },
			"TXT" => { RecordType::TXT },
			"URI" => { RecordType::URI },
			"ZONEMD" => { RecordType::ZONEMD },
			_ => {RecordType::RecordTypeOther }
		}

	}

	fn to_string( &self ) -> String {
		match self {
			RecordType::A => { "A" },
			RecordType::AAAA => { "AAAA" },
			RecordType::AFSDB => { "AFSDB" },
			RecordType::APL => { "APL" },
			RecordType::CAA => { "CAA" },
			RecordType::CDNSKEY => { "CDNSKEY" },
			RecordType::CDS => { "CDS" },
			RecordType::CERT => { "CERT" },
			RecordType::CNAME => { "CNAME" },
			RecordType::CSYNC => { "CSYNC" },
			RecordType::DHCID => { "DHCID" },
			RecordType::DLV => { "DLV" },
			RecordType::DNAME => { "DNAME" },
			RecordType::DNSKEY => { "DNSKEY" },
			RecordType::DS => { "DS" },
			RecordType::EUI48 => { "EUI48" },
			RecordType::EUI64 => { "EUI64" },
			RecordType::HINFO => { "HINFO" },
			RecordType::HIP => { "HIP" },
			RecordType::HTTPS => { "HTTPS" },
			RecordType::IPSECKEY => { "IPSECKEY" },
			RecordType::KEY => { "KEY" },
			RecordType::KX => { "KX" },
			RecordType::LOC => { "LOC" },
			RecordType::MX => { "MX" },
			RecordType::NAPTR => { "NAPTR" },
			RecordType::NS => { "NS" }, 
			RecordType::NSEC => { "NSEC" },
			RecordType::NSEC3 => { "NSEC3" },
			RecordType::NSEC3PARAM => { "NSEC3PARAM" },
			RecordType::OPENPGPKEY => { "OPENPGPKEY" },
			RecordType::PTR => { "PTR" },
			RecordType::RRSIG => { "RRSIG" },
			RecordType::RP => { "RP" },
			RecordType::SIG => { "SIG" },
			RecordType::SMIMEA => { "SMIMEA" },
			RecordType::SOA => { "SOA" },
			RecordType::SRV => { "SRV" },
			RecordType::SSHFP => { "SSHFP" },
			RecordType::SVCB => { "SVCB" },
			RecordType::TA => { "TA" },
			RecordType::TKEY => { "TKEY" },
			RecordType::TLSA => { "TLSA" },
			RecordType::TSIG => { "TSIG" },
			RecordType::TXT => { "TXT" },
			RecordType::URI => { "URI" },
			RecordType::ZONEMD => { "ZONEMD" },
			RecordType::RecordTypeOther => { "" },
			RecordType::Directive => { "$" }
		}.to_string()
	}


}

impl std::fmt::Display for RecordType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.to_string())
	}
}

/** 
 * Zone Record Implementation
 */
impl ZoneRecord {
	

	pub fn create( line : & tokenizer::ZoneLine ) -> Result<Box<dyn IZoneRecord>, String> {

		let mut line_iter: std::slice::Iter<tokenizer::ZoneToken> = line.tokens.iter();

		let tok = match line_iter.next() { 
			None => { return Err("EOL".to_string()); }
			Some(a) => { a }
		};

		if tok.token.starts_with("$") {
			let mut r = Box::<ZoneDirective>::new( Default::default() );
			r.name = tok.token[1..].to_string().clone();
			r.from_iter(&mut line_iter)?;
			return Ok(r);
		} else {
			let mut r = Box::<ZoneRecord>::new( Default::default() );
			r.name.name = tok.token.clone();
			r.from_iter(&mut line_iter)?;
			return Ok(r);
		}


	}
	
	/*
		The origin function will apply the domain origin, which is the rest of the domain name,
		to this zone record name as well as the rdata
	 */
	pub fn origin( &mut self, origin : &String ) {
		self.name.origin( origin );
		match &mut self.rdata {
			Some(r) => {
				r.origin(origin);
			},
			None => { }
		}
	}

	/*
	 * Create a zone record from the wire format that was returned from the dns query 
	 */
	pub fn create_from_wire(  buff : &[u8], offset : &mut usize ) -> Result<Self, String> {

		let mut record = Self { ..Default::default() };

		record.name.name = query::read_qname(buff,offset).as_str().to_string();
		record.name.fqdn = record.name.name.clone();

		record.record_type = RecordType::from_u16(&query::dns_read_int!(u16, buff, offset));
		record.class = query::NSClass::from_u16(&query::dns_read_int!(u16, buff, offset));
		record.ttl = query::dns_read_int!(i32, buff, offset);
		let rdlength = query::dns_read_int!(u16, buff, offset);

		println_verbose!(VERBOSE3, "offset {} name {} type {} ttl {} rdlength {}", offset, record.name.fqdn, record.record_type, record.ttl, rdlength);

		let mut rdata = rr::create_from_type(record.record_type);
		rdata.from_wire(rdlength, buff, offset)?;
		record.rdata = Some(rdata);
		
		Ok(record)
	}

	/**
	 * If the zone record provided is an Address record of A or AAAA it will return
	 * the corresponding IP ADdress
	 */
	pub fn record_to_address( record : &ZoneRecord ) -> Option<std::net::IpAddr> {
		
		if let Some(rd) = &record.rdata {
			
			if let Some(rec) = rd.as_any().downcast_ref::<rr::RDATAa>() {
				return Some(std::net::IpAddr::from( rec.ip ));
			}
			
			if let Some(rec) = rd.as_any().downcast_ref::<rr::RDATAaaaa>() {
				return Some(std::net::IpAddr::from( rec.ip ));
			}
		}

		None

	}


}


impl Default for ZoneRecord {

	fn default() -> Self {
		ZoneRecord {
			name: Default::default(),
			ttl : 0,
			class: query::NSClass::C_IN,
			record_type : RecordType::RecordTypeOther,
			record_type_other: None,
			rdata:  None
		}
	}

}

impl std::fmt::Display for ZoneRecord {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let mut v: String = format!( "{}\t", self.name.name);

		if self.ttl > 0 {
			v += &format!("{}\t", self.ttl);
		}

		let record_type = 
			if self.record_type == RecordType::RecordTypeOther { 
				match &self.record_type_other {
					Some(rec) => { rec.to_string() },
					None => { "__invalid_record_type__".to_string() }
				}
			} else {
				self.record_type.to_string()
			};

		v += &format!("{}\t{}\t", self.class.to_string(), record_type);

		match &self.rdata {
			Some(rd) => { v += &format!("{}\t", rd.to_string() ); },
			None => {} 
		}

		write!(f, "{}", v)
	}
}

impl IZoneRecord for ZoneRecord {

	fn from_iter( &mut self, line_iter : &mut std::slice::Iter<tokenizer::ZoneToken> ) -> Result< (), String> {

		let mut rec_pos = RecordPos::TTL;

		let mut rdata_tokens : Vec<&tokenizer::ZoneToken> = Vec::new();

		loop {
			let tok = match line_iter.next() {
				None => { break; }
				Some(a) => { a }
			};

			if tok.token_type == tokenizer::TokenType::TypeWhite {
				continue;
			}

			if rec_pos == RecordPos::TTL {

				match tok.token.parse::<i32>() {
					Ok(t) => {
						self.ttl = t;
						rec_pos = RecordPos::IN;
					}, 
					Err(e) => {
						if 
							tok.token.to_ascii_uppercase() == "IN" ||
							tok.token.to_ascii_uppercase() == "CS" ||
							tok.token.to_ascii_uppercase() == "CH" ||
							tok.token.to_ascii_uppercase() == "HS"
						{
							self.class = query::NSClass::from_string( &tok.token );
							rec_pos = RecordPos::RTYPE;
						} else {
							return Err(format!("invalid TTL, got '{}' at line {} ({e}) ", tok.token, tok.line));
						}
					}
				}

			} else if rec_pos == RecordPos::IN {
				if 
					tok.token.to_ascii_uppercase() == "IN" ||
					tok.token.to_ascii_uppercase() == "CS" ||
					tok.token.to_ascii_uppercase() == "CH" ||
					tok.token.to_ascii_uppercase() == "HS"
				{
					self.class = query::NSClass::from_string( &tok.token );
					rec_pos = RecordPos::RTYPE;
				} else {
					return Err( format!("Record class is of an invalid type, expected IN,CS,CH,HS got '{}' at line {}", tok.token, tok.line ));
				}
			} else if rec_pos == RecordPos::RTYPE {
				self.record_type = RecordType::from_string( &tok.token );
				if self.record_type == RecordType::RecordTypeOther {
					self.record_type_other = Some(tok.token.clone());
				}
				rec_pos = RecordPos::RDATA;
			} else {
				rdata_tokens.push( tok );
			}

			// every command should have whitespace after it maybe, enforce that
			match line_iter.next() {
				None => { break; }
				Some(a) => { 
					if a.token_type != tokenizer::TokenType::TypeWhite {
						return Err( format!(
							"Expected whitespace, got '{}' at line {}",
							tok.token,
							tok.line
						));
					}
				}
			};

		};

		self.rdata = Some(rr::create_from_type( self.record_type ));
		if let Some(m) = &mut self.rdata {
			m.from_tokens( &rdata_tokens )?;
		}

		Ok(())

	}

	fn as_any( &mut self) -> &mut dyn std::any::Any {
		self
	}

}

impl Clone for ZoneRecord {
	fn clone(&self) -> Self {
		let mut new_rd : Option<Box<dyn rr::RecordRDATA>> = None;
		
		if let Some(rd) = self.rdata.as_ref() {
			new_rd = Some( rd.clone_box() );
		}

		Self {
			name: self.name.clone(),
			ttl: self.ttl,
			class: self.class.clone(),
			record_type: self.record_type.clone(),
			record_type_other: self.record_type_other.clone(),
			rdata: new_rd
		}
	}
	
}


/**
 * Directive, like $TTL
 */
pub struct ZoneDirective {
	pub name : String,
	pub value : String 
}

impl IZoneRecord for ZoneDirective {

    fn from_iter( &mut self, iter : &mut std::slice::Iter<tokenizer::ZoneToken> ) -> Result< (), String> {
		
		loop {
			match iter.next() {
				Some(m) => {
					if m.token_type != tokenizer::TokenType::TypeWhite {
						self.value = m.token.clone();
						return Ok(());
					}
				}, 
				None => {
					break;
				}
			}
		};

		Err("EOL".to_string())
    }

	fn as_any( &mut self) -> &mut dyn std::any::Any {
		self
	}
}

impl Default for ZoneDirective {
	fn default() -> Self {
		ZoneDirective {
			name: String::new(),
			value : String::new()
		}
	}
}

impl std::fmt::Display for ZoneDirective {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "${} {}", self.name, self.value)
	}
}

impl Clone for ZoneDirective {
	fn clone(&self) -> Self {
		Self {
			name: self.name.clone(),
			value: self.value.clone()
		}
	}
}