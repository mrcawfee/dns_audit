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

use crate::{root, query::{self}, zone};
use std::{sync::{Arc, RwLock}};

#[derive(Serialize, Deserialize)]
pub enum ErrorCode {
	NoAuthoratative,
	AuthoratativeFail,
	NoResolve,
	ResolveIpNotMatch
}

#[derive(Serialize, Deserialize)]
pub struct MonitorResult {
	pub domain_name : String,
	pub success : bool,
	pub reason : Vec<String>,
	pub flags : Vec<ErrorCode>,
	pub nameservers : Option<Vec<String>>,
	pub ips : Option<Vec<std::net::IpAddr>>
}

impl std::fmt::Display for MonitorResult {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.success {
			writeln!(f, "{} OK", self.domain_name)?;
		} else {
			writeln!(f, "{} FAIL", self.domain_name)?;
			writeln!(f, "\t{}", self.reason.join("\n\t"))?;
		}
		Ok(())
    }

}

#[derive(Serialize, Deserialize)]
pub struct Monitor {
	pub domain_name : String,
	pub ns : Option<Vec<String>>,
	pub ip : Option<Vec<std::net::IpAddr>>
}

impl Monitor {

	/**
	 * this function will test to make sure the ns and ip address
	 * it will return true if everything matches, or false if not
	 */
	pub fn test( inme : &Arc<RwLock<Monitor>>, root : &mut root::Root ) -> MonitorResult {

		let me = &inme.read().unwrap();

		let mut rval: MonitorResult = MonitorResult {
			domain_name : me.domain_name.clone(),
            success: true,
			reason : Vec::new(),
			flags: Vec::new(),
            nameservers: None,
            ips: None,
        };


		let mut read_ns: Vec<String> = Vec::new();

		if let Ok(m) = root.get_nameservers_and_resolve(&me.domain_name) {
			let root_ns = &m.read().unwrap();
			for addr in &root_ns.servers {

				let mut query = query::Sender::new( &addr.ip );
				if let Ok(_) = query.query( &me.domain_name, query::QueryType::T_NS) {
					for rec in &query.authority {
						if rec.record_type == zone::record::RecordType::NS {
							if let Some(namerr) = rec.rdata.as_ref().unwrap().as_any().downcast_ref::<zone::rr::RDATANameRR>() {
								read_ns.push( namerr.name.fqdn.clone());
							}
						}
					}
					break;
				}
			}

		}

		if let Some(ns) = &me.ns {

			if read_ns.len() == 0 {
				rval.flags.push(ErrorCode::NoAuthoratative);
				rval.reason.push( "no authoratative nameservers at root".to_string() );
				rval.success = false;
			} else if read_ns.len() != ns.len() {
				rval.reason.push( "nameservers at root do not match expected".to_string() );
				rval.flags.push(ErrorCode::AuthoratativeFail);
				rval.success = false;
			} else {
				for nsname in ns {
					let mut fail = true;

					for cmpns in &read_ns {
						if cmpns.eq_ignore_ascii_case( &nsname ) {
							fail = false;
							break;
						}
					}

					if fail {
						rval.reason.push( "nameservers at root do not match expected".to_string() );
						rval.flags.push(ErrorCode::AuthoratativeFail);
						rval.success = false;
						break;
					}
				}
			}

		}

		rval.nameservers = Some( read_ns );


		if let Some(ips) = &me.ip {

			for auth_ns in rval.nameservers.as_ref().unwrap() {

				let mut result_from_ns = false;

				let mut read_addresses : Vec<std::net::IpAddr> = Vec::new();
				if let Ok( addresses ) = dns_lookup::lookup_host( &auth_ns ) {	
					for addr in addresses {

						let mut query = query::Sender::new( &addr );
						if let Ok(_) = query.query( &me.domain_name, query::QueryType::T_A) {

							result_from_ns = true;

							for res in &query.answer {
								if res.record_type == zone::record::RecordType::A {
									if let Some(a) = res.rdata.as_ref().unwrap().as_any().downcast_ref::<zone::rr::RDATAa>() {
										read_addresses.push( std::net::IpAddr::from(a.ip.clone())) ;
									}
								}
							}
						}

						if let Ok(_) = query.query( &me.domain_name, query::QueryType::T_AAAA) {

							result_from_ns = true;

							for res in &query.answer {
								if res.record_type == zone::record::RecordType::A {
									if let Some(a) = res.rdata.as_ref().unwrap().as_any().downcast_ref::<zone::rr::RDATAaaaa>() {
										read_addresses.push( std::net::IpAddr::from(a.ip.clone())) ;
									}
								}
							}
						}

						if result_from_ns {
							break;
						}

					}
				}
				
				if result_from_ns {
					rval.ips = Some(read_addresses);

					if rval.ips.as_ref().unwrap().len() == 0 { 
						rval.flags.push(ErrorCode::NoResolve);
						rval.reason.push( "domain did not resolve".to_string() );
						rval.success = false;
					} else if rval.ips.as_ref().unwrap().len() != ips.len() {
						rval.flags.push(ErrorCode::ResolveIpNotMatch);
						rval.reason.push( "did not return the correct ips".to_string() );
						rval.success = false;
					} else {
						for ip in rval.ips.as_ref().unwrap() {
							let mut found = false;
							for ip2 in ips {
								if ip == ip2 {
									found = true;
									break;
								}
							}
							if !found {
								rval.flags.push(ErrorCode::ResolveIpNotMatch);
								rval.reason.push( "did not return the correct ips".to_string() );
								rval.success = false;
							}
						}
					}

					break;
				}

			}

		}


		rval
	}

	pub fn normalize(&mut self) {

		if let Some(ns) = &mut self.ns {
			for name in ns {
				if !name.ends_with(&".".to_string()) {
					name.push('.');
				}
			}
		}

	}

}
