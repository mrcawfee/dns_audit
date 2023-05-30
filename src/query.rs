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


use std::{net::{UdpSocket, SocketAddr}};
use super::zone;

extern crate arrayvec;
use crate::config::{println_verbose, print_verbose};

/**
 * macro function to convert an arbitrary integer from big endian into the int type specified by t
 * 
 * Usage dns_read_int( int_type, buffer, offset ) where int_type is a primiitive type like u16
 */
macro_rules! dns_read_int {
	($t:ident, $buff:expr, $offset:expr) => {
		$t::from_be_bytes( crate::query::read_buff(&$buff, $offset, std::mem::size_of::<$t>() ).try_into().unwrap() )
	};
}
pub(crate) use dns_read_int;

pub trait Wire {

	/**
	 * Write this object into the DNS wire format
	 */
	fn write( &self ) -> Vec<u8>;

	/**
	 * Read this object's values from the dns wire format
	 * buff : is the buffer
	 * offset : is the offset from the start of the buffer for where we are to read
	 */
	fn read ( &mut self, buff : &[u8], offset: &mut usize );

}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq,Clone,Copy)]
pub enum NSClass {
	C_INVALID = 0,	/*%< Cookie. */
	C_IN = 1,		/*%< Internet. */
	C_2 = 2,		/*%< unallocated/unsupported. */
	C_CHAOS = 3,		/*%< MIT Chaos-net. */
	C_HS = 4,		/*%< MIT Hesiod. */
	/* Query class values which do not appear in resource records */
	C_NONE = 254,	/*%< for prereq. sections in update requests */
	C_ANY = 255,		/*%< Wildcard match. */
	C_MAX = 65535
} 

impl NSClass {
	pub fn as_u16(&self) -> u16 {
		unsafe {
			let me : *const NSClass = self;
			*me as u16
		}
	}
	pub fn from_u16( indata : &u16) -> NSClass {
		match indata {
			0 => { Self::C_INVALID },	/*%< Cookie. */
			1 => { Self::C_IN },		/*%< Internet. */
			2 => { Self::C_2 },		/*%< unallocated/unsupported. */
			3 => { Self::C_CHAOS },		/*%< MIT Chaos-net. */
			4 => { Self::C_HS },		/*%< MIT Hesiod. */
			/* Query class values which do not appear in resource records */
			254 => { Self::C_NONE },	/*%< for prereq. sections in update requests */
			255 => { Self::C_ANY },		/*%< Wildcard match. */
			_ => { Self::C_INVALID }
		}
	}

	pub fn from_string( instr : &str) -> Self {
		match instr.to_ascii_uppercase().as_str() {
			"IN" => { Self::C_IN },
			"CH" => { Self::C_CHAOS },
			"HS" => { Self::C_HS},
			_ => { Self::C_INVALID }
		}
	}
	pub fn to_string( &self ) -> String {
		match self {
			Self::C_IN => { "IN "},
			Self::C_CHAOS => { "CH" },
			Self::C_HS => { "HS" },
			_ => {"INVALID"}
		}.to_string()
	}
}

#[repr(u16)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq,Clone,Copy)]
pub enum QueryType {
	T_INVALID = 0,
	T_A = 1,
	T_NS = 2,
	T_MD = 3,
	T_MF = 4,
	T_CNAME = 5,
	T_SOA = 6,
	T_MB = 7,
	T_MG = 8,
	T_MR = 9,
	T_NULL = 10,
	T_WKS = 11,
	T_PTR = 12,
	T_HINFO = 13,
	T_MINFO = 14,
	T_MX = 15,
	T_TXT = 16,
	T_RP = 17,
	T_AFSDB = 18,
	T_X25 = 19,
	T_ISDN = 20,
	T_RT = 21,
	T_NSAP = 22,
	T_NSAP_PTR = 23,
	T_SIG = 24,
	T_KEY = 25,
	T_PX = 26,
	T_GPOS = 27,
	T_AAAA = 28,
	T_LOC = 29,
	T_NXT = 30,
	T_EID = 31,
	T_NIMLOC = 32,
	T_SRV = 33,
	T_ATMA = 34,
	T_NAPTR = 35,
	T_KX = 36,
	T_CERT = 37,
	T_A6 = 38,
	T_DNAME = 39,
	T_SINK = 40,
	T_OPT = 41,
	T_APL = 42,
	T_DS = 43,
	T_SSHFP = 44,
	T_IPSECKEY = 45,
	T_RRSIG = 46,
	T_NSEC = 47,
	T_DNSKEY = 48,
	T_DHCID = 49,
	T_NSEC3 = 50,
	T_NSEC3PARAM = 51,
	T_TLSA = 52,
	T_SMIMEA = 53,
	T_HIP = 55,
	T_NINFO = 56,
	T_RKEY = 57,
	T_TALINK = 58,
	T_CDS = 59,
	T_CDNSKEY = 60,
	T_OPENPGPKEY = 61,
	T_CSYNC = 62,
	T_SPF = 99,
	T_UINFO = 100,
	T_UID = 101,
	T_GID = 102,
	T_UNSPEC = 103,
	T_NID = 104,
	T_L32 = 105,
	T_L64 = 106,
	T_LP = 107,
	T_EUI48 = 108,
	T_EUI64 = 109,
	T_TKEY = 249,
	T_TSIG = 250,
	T_IXFR = 251,
	T_AXFR = 252,
	T_MAILB = 253,
	T_MAILA = 254,
	T_ANY = 255,
	T_URI = 256,
	T_CAA = 257,
	T_AVC = 258,
	T_TA = 32768,
	T_DLV = 32769
}

impl QueryType {
	pub fn as_u16(&self) -> u16 {
		unsafe {
			let me : *const QueryType = self;
			*me as u16
		}
	}

	pub fn from_u16( indata : &u16 ) -> Self {
		match indata {
			1 => { Self::T_A },
			2 => { Self::T_NS },
			3 => { Self::T_MD },
			4 => { Self::T_MF },
			5 => { Self::T_CNAME },
			6 => { Self::T_SOA },
			7 => { Self::T_MB },
			8 => { Self::T_MG },
			9 => { Self::T_MR },
			10 => { Self::T_NULL },
			11 => { Self::T_WKS },
			12 => { Self::T_PTR },
			13 => { Self::T_HINFO },
			14 => { Self::T_MINFO },
			15 => { Self::T_MX },
			16 => { Self::T_TXT },
			17 => { Self::T_RP },
			18 => { Self::T_AFSDB },
			19 => { Self::T_X25 },
			20 => { Self::T_ISDN },
			21 => { Self::T_RT },
			22 => { Self::T_NSAP },
			23 => { Self::T_NSAP_PTR },
			24 => { Self::T_SIG },
			25 => { Self::T_KEY },
			26 => { Self::T_PX },
			27 => { Self::T_GPOS },
			28 => { Self::T_AAAA },
			29 => { Self::T_LOC },
			30 => { Self::T_NXT },
			31 => { Self::T_EID },
			32 => { Self::T_NIMLOC },
			33 => { Self::T_SRV },
			34 => { Self::T_ATMA },
			35 => { Self::T_NAPTR },
			36 => { Self::T_KX },
			37 => { Self::T_CERT },
			38 => { Self::T_A6 },
			39 => { Self::T_DNAME },
			40 => { Self::T_SINK },
			41 => { Self::T_OPT },
			42 => { Self::T_APL },
			43 => { Self::T_DS },
			44 => { Self::T_SSHFP },
			45 => { Self::T_IPSECKEY },
			46 => { Self::T_RRSIG },
			47 => { Self::T_NSEC },
			48 => { Self::T_DNSKEY },
			49 => { Self::T_DHCID },
			50 => { Self::T_NSEC3 },
			51 => { Self::T_NSEC3PARAM },
			52 => { Self::T_TLSA },
			53 => { Self::T_SMIMEA },
			55 => { Self::T_HIP },
			56 => { Self::T_NINFO },
			57 => { Self::T_RKEY },
			58 => { Self::T_TALINK },
			59 => { Self::T_CDS },
			60 => { Self::T_CDNSKEY },
			61 => { Self::T_OPENPGPKEY },
			62 => { Self::T_CSYNC },
			99 => { Self::T_SPF },
			100 => { Self::T_UINFO },
			101 => { Self::T_UID },
			102 => { Self::T_GID },
			103 => { Self::T_UNSPEC },
			104 => { Self::T_NID },
			105 => { Self::T_L32 },
			106 => { Self::T_L64 },
			107 => { Self::T_LP },
			108 => { Self::T_EUI48 },
			109 => { Self::T_EUI64 },
			249 => { Self::T_TKEY },
			250 => { Self::T_TSIG },
			251 => { Self::T_IXFR },
			252 => { Self::T_AXFR },
			253 => { Self::T_MAILB },
			254 => { Self::T_MAILA },
			255 => { Self::T_ANY },
			256 => { Self::T_URI },
			257 => { Self::T_CAA },
			258 => { Self::T_AVC },
			32768 => { Self::T_TA },
			32769 => { Self::T_DLV },
			_ => { Self::T_INVALID }
		}
	}
}

impl std::fmt::Display for QueryType {

	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"{}",
			match self {
				Self::T_INVALID => { "T_INVALID" },
				Self::T_A => { "T_A" },
				Self::T_NS => { "T_NS" },
				Self::T_MD => { "T_MD" },
				Self::T_MF => { "T_MF" },
				Self::T_CNAME => { "T_CNAME" },
				Self::T_SOA => { "T_SOA" },
				Self::T_MB => { "T_MB" },
				Self::T_MG => { "T_MG" },
				Self::T_MR => { "T_MR" },
				Self::T_NULL => { "T_NULL" },
				Self::T_WKS => { "T_WKS" },
				Self::T_PTR => { "T_PTR" },
				Self::T_HINFO => { "T_HINFO" },
				Self::T_MINFO => { "T_MINFO" },
				Self::T_MX => { "T_MX" },
				Self::T_TXT => { "T_TXT" },
				Self::T_RP => { "T_RP" },
				Self::T_AFSDB => { "T_AFSDB" },
				Self::T_X25 => { "T_X25" },
				Self::T_ISDN => { "T_ISDN" },
				Self::T_RT => { "T_RT" },
				Self::T_NSAP => { "T_NSAP" },
				Self::T_NSAP_PTR => { "T_NSAP_PTR" },
				Self::T_SIG => { "T_SIG" },
				Self::T_KEY => { "T_KEY" },
				Self::T_PX => { "T_PX" },
				Self::T_GPOS => { "T_GPOS" },
				Self::T_AAAA => { "T_AAAA" },
				Self::T_LOC => { "T_LOC" },
				Self::T_NXT => { "T_NXT" },
				Self::T_EID => { "T_EID" },
				Self::T_NIMLOC => { "T_NIMLOC" },
				Self::T_SRV => { "T_SRV" },
				Self::T_ATMA => { "T_ATMA" },
				Self::T_NAPTR => { "T_NAPTR" },
				Self::T_KX => { "T_KX" },
				Self::T_CERT => { "T_CERT" },
				Self::T_A6 => { "T_A6" },
				Self::T_DNAME => { "T_DNAME" },
				Self::T_SINK => { "T_SINK" },
				Self::T_OPT => { "T_OPT" },
				Self::T_APL => { "T_APL" },
				Self::T_DS => { "T_DS" },
				Self::T_SSHFP => { "T_SSHFP" },
				Self::T_IPSECKEY => { "T_IPSECKEY" },
				Self::T_RRSIG => { "T_RRSIG" },
				Self::T_NSEC => { "T_NSEC" },
				Self::T_DNSKEY => { "T_DNSKEY" },
				Self::T_DHCID => { "T_DHCID" },
				Self::T_NSEC3 => { "T_NSEC3" },
				Self::T_NSEC3PARAM => { "T_NSEC3PARAM" },
				Self::T_TLSA => { "T_TLSA" },
				Self::T_SMIMEA => { "T_SMIMEA" },
				Self::T_HIP => { "T_HIP" },
				Self::T_NINFO => { "T_NINFO" },
				Self::T_RKEY => { "T_RKEY" },
				Self::T_TALINK => { "T_TALINK" },
				Self::T_CDS => { "T_CDS" },
				Self::T_CDNSKEY => { "T_CDNSKEY" },
				Self::T_OPENPGPKEY => { "T_OPENPGPKEY" },
				Self::T_CSYNC => { "T_CSYNC" },
				Self::T_SPF => { "T_SPF" },
				Self::T_UINFO => { "T_UINFO" },
				Self::T_UID => { "T_UID" },
				Self::T_GID => { "T_GID" },
				Self::T_UNSPEC => { "T_UNSPEC" },
				Self::T_NID => { "T_NID" },
				Self::T_L32 => { "T_L32" },
				Self::T_L64 => { "T_L64" },
				Self::T_LP => { "T_LP" },
				Self::T_EUI48 => { "T_EUI48" },
				Self::T_EUI64 => { "T_EUI64" },
				Self::T_TKEY => { "T_TKEY" },
				Self::T_TSIG => { "T_TSIG" },
				Self::T_IXFR => { "T_IXFR" },
				Self::T_AXFR => { "T_AXFR" },
				Self::T_MAILB => { "T_MAILB" },
				Self::T_MAILA => { "T_MAILA" },
				Self::T_ANY => { "T_ANY" },
				Self::T_URI => { "T_URI" },
				Self::T_CAA => { "T_CAA" },
				Self::T_AVC => { "T_AVC" },
				Self::T_TA => { "T_TA" },
				Self::T_DLV => { "T_DLV" }
			}
		)
	}
}

#[repr(u8)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq,Clone,Copy)]
pub enum RCODE {
	NOERROR=0,
	FORMERR=1,
	SERVFAIL=2,
	NXDOMAIN=3,
	NOTIMPL=4,
	REFUSED=5,
	YXDOMAIN = 6,
	YXRRSET = 7,
	NXRRSET = 8,
	NOTAUTH = 9,
	NOTZONE = 10,
}

impl RCODE {
	pub fn as_u8(&self) -> u8 {
		unsafe {
			let me : *const RCODE = self;
			*me as u8
		}
	}

	pub fn from_u8( number : u8 ) -> RCODE {
		match number {
			0 => { Self::NOERROR },
			1 => { Self::FORMERR },
			2 => { Self::SERVFAIL },
			3 => { Self::NXDOMAIN },
			4 => { Self::NOTIMPL },
			5 => { Self::REFUSED },
			6 => { Self::YXDOMAIN },
			7 => { Self::YXRRSET },
			8 => { Self::NXRRSET },
			9 => { Self::NOTAUTH },
			10 => { Self::NOTZONE },
			_ => { Self::NOTIMPL }
		}
	}
}

impl std::fmt::Display for RCODE {

	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", match self {
			RCODE::NOERROR=>{"NOERROR"},
			RCODE::FORMERR=>{"FORMERR"},
			RCODE::SERVFAIL=>{"SERVFAIL"},
			RCODE::NXDOMAIN=>{"NXDOMAIN"},
			RCODE::NOTIMPL=>{"NOTIMPL"},
			RCODE::REFUSED=>{"REFUSED"},
			RCODE::YXDOMAIN =>{"YXDOMAIN"},
			RCODE::YXRRSET =>{"YXRRSET"},
			RCODE::NXRRSET =>{"NXRRSET"},
			RCODE::NOTAUTH =>{"NOTAUTH"},
			RCODE::NOTZONE =>{"NOTZONE"},
		})
	}
}

#[repr(u8)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq,Clone,Copy)]
pub enum OPCODE {
	O_QUERY = 0,
	O_IQUERY = 1,
	O_STATUS = 2,
	O_NOTIFY = 4,
	O_UPDATE = 5
}


impl OPCODE {
	pub fn as_u8(&self) -> u8 {
		unsafe {
			let me : *const OPCODE = self;
			*me as u8
		}
	}

	pub fn from_u8( number : u8 ) -> OPCODE {
		match number {
			0 => { Self::O_QUERY },
			1 => { Self::O_IQUERY },
			2 => { Self::O_STATUS },
			4 => { Self::O_NOTIFY },
			5 => { Self::O_UPDATE },
			_ => { Self::O_QUERY }
		}
	}
}

impl std::fmt::Display for OPCODE {

	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", match self {
			Self::O_QUERY=>{"QUERY"},
			Self::O_IQUERY=>{"IQUERY"},
			Self::O_STATUS=>{"STATUS"},
			Self::O_NOTIFY=>{"NOTIFY"},
			Self::O_UPDATE=>{"UPDATE"}
		})
	}
}
/**
 * helper function to write the inputted byte string into the buffer vector
*/
pub fn write_buff(  buff : &mut Vec<u8>, src : &[u8], offset : usize) -> usize {

	println_verbose!(VERBOSE3, "add '{}' bytes offset {} to buffer", src.len(), offset);

	let end = offset + src.len();
	buff[offset..end].copy_from_slice(src);
	println_verbose!(VERBOSE3, "Done");
	end
}

/**
 * helper function to read SIZE bytes from buffer and return it as a vector, this 
 * is useful as the first step before converting to the final data type
 */
pub fn read_buff( buff : &[u8], offset: &mut usize, size : usize ) -> Vec<u8> {
	
	let end = *offset + size;	
	let rval = buff[*offset..end].to_vec();

	*offset = *offset + size;

	return rval;
}

/**
 * Read a qualified name with compression fun 
 */
pub fn read_qname(buff : &[u8], offset : &mut usize) -> String {
	let mut dest = String::new();
	while *offset < buff.len()  {
		if !qname_namepart( &mut dest, buff, offset) {
			break;
		}
	}
	dest
}

/**
 * each part of the name, with support for dns compression
 */
fn qname_namepart(  dn : &mut String, buffer : &[u8], offset : &mut usize ) -> bool {

	if *offset >= buffer.len() {
		return false;
	}

	let part_len : u8 = dns_read_int!(u8, buffer, offset);

	if part_len == 0 {
		return false;
	}

	const COMP : u8 = 0b11000000;

	if (part_len & COMP) == COMP  {
		// compresed part
		let mut buff2 = [0u8;2];
		buff2[0] = part_len & !COMP;
		buff2[1] = buffer[*offset];

		*offset = *offset + 1;


		let mut usize_com_offset : usize = u16::from_be_bytes(buff2) as usize;
		while usize_com_offset < buffer.len() {
			if !qname_namepart(dn, buffer, &mut usize_com_offset) {
				break;
			}
		}
		return false;
	} else {

		let dn_vec = read_buff(buffer, offset, part_len as usize );

		if dn.len() > 0 {
			dn.push('.');
		}

		for c in dn_vec {
			dn.push( c as char );
		}

	}
	return true;
}

/**
 * Question section from the dns query
 */
pub struct Question {
	host : String,
	qtype : QueryType,
	qclass : NSClass
}

impl Wire for Question {

	/**
	 * write out the question into the raw format that is needed for the dns server
	 */
	#[allow(unused_assignments)]
	fn write( &self ) -> Vec<u8> {		
		let mut buff = Vec::<u8>::new();

		let mut offset : usize = 0;

		let bytes = self.host.as_bytes();

		if  bytes.len() > 255 {
			panic!("host length {} is > 255 which isn't valid for domain names", bytes.len());
		}

		let mut x: u8 = 0;
		let mut last_l :u8 = 0;
		let byte_len :u8 = bytes.len() as u8;


		println_verbose!(VERBOSE3, "bytes len '{}' ", byte_len);

		while x <= byte_len as u8 {
			if x == byte_len || bytes[x as usize] == '.' as u8 {
				let part_len : u8 = x - last_l;
				if part_len == 0 { 
					last_l = x;
					x = x + 1;
					continue;
				}

				// add part + 1 
				buff.resize( buff.len() + part_len as usize + 1, 0u8);

				offset = write_buff(&mut buff, &part_len.to_be_bytes(), offset);

				let end : u8 = last_l + part_len;

				offset = write_buff(&mut buff, &bytes[last_l as usize..end as usize], offset);
				last_l = x + 1;
			}

			x = x + 1;

		}

		println_verbose!(VERBOSE3, "host done");

		buff.resize( buff.len() + 5, 0u8);
		offset = write_buff(&mut buff, &0u8.to_be_bytes(), offset);
		offset = write_buff(&mut buff, &self.qtype.as_u16().to_be_bytes(), offset);
		offset = write_buff(&mut buff, &self.qclass.as_u16().to_be_bytes(), offset);

		buff
	}

	fn read ( &mut self, buff : &[u8], offset: &mut usize ) {
		self.host = read_qname(buff, offset);
		self.qtype = QueryType::from_u16( &dns_read_int!(u16, buff, offset));
		self.qclass = NSClass::from_u16( &dns_read_int!(u16, buff, offset));
	}

}

impl Default for Question {
	fn default() -> Self {
		Self {
			host: String::new(),
			qtype: QueryType::T_INVALID,
			qclass: NSClass::C_INVALID,
		}
	}
}

impl std::fmt::Display for Question {
	
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "host={} qtype={} class={}", self.host, self.qtype.as_u16(), self.qclass.as_u16())
	}

}

/**
 * DNS Header
 */
#[repr(C)]
pub struct Header {
	pub id : u16,
	pub qr: bool, // is a query
	pub opcode: OPCODE, // 
	pub aa : bool,
	pub tc : bool,
	pub rd :bool,
	pub ra: bool,
	pub z: u8,
	pub rcode : RCODE,
	pub qdcount : u16,
	pub ancount : u16,
	pub nscount : u16,
	pub arcount : u16	
}

impl Wire for Header {

	/**
	 * Write the header and return the byte vector in the DNS wire format
	 */
	#[allow(unused_assignments)] // for the last offset
	fn write( &self) -> Vec<u8> {
		let mut buff = vec![0u8; 12];

		let mut offset = 0;
		offset = write_buff(&mut buff, &self.id.to_be_bytes(), offset);

		// boo lack of union bit offsets
		let mut flag1 :u8 = 0;
		if self.rd {
			flag1 |= 0b10000000;
		}
		if self.tc {
			flag1 |= 0b01000000;
		}
		if self.aa {
			flag1 |= 0b00100000;
		}
		flag1 |= 0b00011110 & (self.opcode.as_u8() << 1);
		if self.qr {
			flag1 |= 0b00000001;
		}
		offset = write_buff(&mut buff, &flag1.to_be_bytes(), offset);


		let mut flag2 :u8 = 0;
		flag2 |= 0b11110000 & (self.rcode.as_u8() << 4);
		flag2 |= 0b00001110 & (self.z << 1);
		if self.ra {
			flag2 |= 0b00000001
		}
		offset = write_buff(&mut buff, &flag2.to_be_bytes(), offset);
		offset = write_buff(&mut buff, &self.qdcount.to_be_bytes(), offset);
		offset = write_buff(&mut buff, &self.ancount.to_be_bytes(), offset);
		offset = write_buff(&mut buff, &self.nscount.to_be_bytes(), offset);
		offset = write_buff(&mut buff, &self.arcount.to_be_bytes(), offset);

		return buff;
	}

	/**
	 * read and set our properties in the wire format from the read buffer
	 * offsetted by x bytes, after it is read the offset will point to 12
	 * bytes past it's starting point
	 */
	fn read ( &mut self, buff : &[u8], offset: &mut usize ) {
		self.id = dns_read_int!(u16, buff, offset);

		let flag1 : u8 = dns_read_int!(u8, buff, offset);
		self.qr 		= if (flag1 & 0b10000000) != 0 { true } else { false };
		self.opcode 	= OPCODE::from_u8((flag1 & 0b01111000) >> 1);
		self.aa 		= if (flag1 & 0b00000100) != 0 { true } else { false };
		self.tc 		= if (flag1 & 0b00000010) != 0 { true } else { false };
		self.rd 		= if (flag1 & 0b00000001) != 0 { true } else { false };

		let flag2 : u8 = dns_read_int!(u8, buff, offset);
		self.ra 		= if (flag2 & 0b10000000) != 0 { true } else { false };
		self.z  		=    (flag2 & 0b01110000) >> 4 ;
		self.rcode	 	=    RCODE::from_u8(flag2 & 0b00001111);

		self.qdcount = dns_read_int!(u16, buff, offset);
		self.ancount = dns_read_int!(u16, buff, offset);
		self.nscount = dns_read_int!(u16, buff, offset);
		self.arcount = dns_read_int!(u16, buff, offset);
	}


}

impl Default for Header {
	fn default() -> Self {
		Self {
			id: 0,
			qdcount: 0,
			ancount: 0,
			nscount: 0,
			arcount: 0,
			qr: false,
			opcode: OPCODE::O_QUERY,
			aa: false,
			tc: false,
			rd: false,
			ra: false,
			z: 0,
			rcode: RCODE::NOERROR
		}
	}
}

impl std::fmt::Display for Header {

	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f, 
			"id={} rd={} tc={} aa={} opcode={} qr={} rcode={} z={} ra={} qdcount={} ancount={} nscount={} arcount={} ",
			self.id,
			self.rd,
			self.tc,
			self.aa,
			self.opcode,
			self.qr,
			self.rcode,
			self.z,
			self.ra,
			self.qdcount,
			self.ancount,
			self.nscount,
			self.arcount
		)
	}
}

/**
 * This structure is our sender to the DNS server, this does not recurse to the final server and just
 * queries this specific server. 
 * Usage:
 *   let mut sender = Sender::New( std::net::IpAddr::V4(...) )
 *   sender.query( "domain.name", T_NS )
 */
pub struct Sender {
	server: std::net::IpAddr,
	pub timeout : std::time::Duration,
	pub recursive : bool,
	pub recv_header : Header,
	pub recv_questions : Vec<Question>,
	pub answer : Vec<zone::record::ZoneRecord>,
	pub authority : Vec<zone::record::ZoneRecord>,
	pub additional : Vec<zone::record::ZoneRecord>,
}

impl Sender {

	pub fn new( server : &std::net::IpAddr) -> Self {
		Self {
			server :server.clone(),
			timeout : std::time::Duration::new(5,0),
			recv_header: Default::default(),
			recursive : false ,
			recv_questions : Vec::new(),
			answer: Vec::new(),
			authority: Vec::new(),
			additional: Vec::new()
		}
	}

	pub fn query( &mut self, host : & String , query_type : QueryType ) -> Result<(),String>{

		let socket = match UdpSocket::bind("0.0.0.0:0") {
			Ok(m) => { m },
			Err(e) => { return Err(format!("bind failed {}", e).to_string()); }
		};

		let sockaddr = SocketAddr::new(self.server.clone(), 53);

		println_verbose!(VERBOSE2, "Querying {} for rec {} at '{:?}'", host, query_type, sockaddr);

		if let Err(e) =  socket.connect(sockaddr) {
			return Err(format!("connect failed {}", e).to_string()); 
		}

		let questions = vec![ 
			Question { 
				host: host.clone(), 
				qtype: query_type.clone(), 
				qclass: NSClass::C_IN
			}
		];

		let mut request : Vec<u8> = Vec::new();

		let send_header = Header  {
			id: 1,
			qdcount: questions.len() as u16,
			ancount: 0,
			nscount: 0,
			arcount: 0,
			qr: false,
			opcode: OPCODE::O_QUERY,
			aa: false,
			tc: false,
			rd: self.recursive,
			ra: false,
			z: 0,
			rcode: RCODE::NOERROR,
		};

		{
			let mut header_bytes = send_header.write();
			request.append( &mut header_bytes );
		}

		println_verbose!(VERBOSE3, "header complete");

		for question in questions {
			let mut q_bytes = question.write();
			request.append(&mut q_bytes);

		}

		println_verbose!(VERBOSE3, "question complete");


		println_verbose!(VERBOSE2, "Sending request of {} bytes\nSEND: {}", (request.len()), send_header);

		if let Err(e) = socket.send( &request ) {
			return Err(format!("send failed {}", e).to_string());
		}

		println_verbose!(VERBOSE2, "send complete");

		if let Err(e) = socket.set_read_timeout(Some( self.timeout.clone() )) {
			return Err( format!("set_read_timeout failed {}", e).to_string() );
		}

		const BUFF_SZ: usize = 512;
		let mut buff = [ 0u8; BUFF_SZ ];
		let read_sz : usize;

		match socket.recv_from(&mut buff) {
			Ok( (size, _addr) ) => {

				println_verbose!(VERBOSE3, "read {} bytes from {}", size, _addr);
				read_sz = size;
			},
			Err(e) => {
				return Err(e.to_string());
			}		
		}

		let mut x : usize = 0;
		let mut y : usize = 0;
		print_verbose!(VERBOSE2, "\t");
		while x < read_sz {
			if y >= 20 {
				y = 0;
				print_verbose!(VERBOSE2, "\n\t");
			}
			print_verbose!(VERBOSE2, "{:02x} ", buff[x]);
			x = x + 1;
			y = y + 1;
		}
		println_verbose!(VERBOSE2);

		let mut offset : usize = 0;

		self.recv_header.read(&buff, &mut offset);

		println_verbose!(VERBOSE3, "READ {} bytes", read_sz);
		println_verbose!(VERBOSE2, "READ: {}", (self.recv_header) );

		// read the question section
		let mut x = 0;
		while x < self.recv_header.qdcount {
			let mut q: Question = Default::default();
			q.read(&buff, &mut offset);
			println_verbose!(VERBOSE2, "READ QUESTION: {}", q);
			self.recv_questions.push( q );
			x = x + 1;
		}

		Self::read_record(&buff, &mut offset, &mut self.answer, self.recv_header.ancount);
		Self::read_record(&buff, &mut offset, &mut self.authority, self.recv_header.nscount);
		Self::read_record(&buff, &mut offset, &mut self.additional, self.recv_header.arcount);
			
		Ok(())
	}

	fn read_record( buff : &[u8], offset : &mut usize, list : & mut Vec<zone::record::ZoneRecord>, rec_count : u16 ) {

		println_verbose!(VERBOSE2, "Reading {} records, cur pos {:b} ", rec_count, buff[*offset]);

		let mut x :u16 = 0;
		while x < rec_count {

			if let Ok(rec) = zone::record::ZoneRecord::create_from_wire( buff, offset ) {
				list.push(rec);
			}
			x = x + 1;
		}
	}

}

impl std::fmt::Display for Sender {

	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Header {}", self.recv_header)?;
		for q in &self.recv_questions {
			write!(f, "Question {}", q)?;
		}
		write!(f, "\n")
	}

}