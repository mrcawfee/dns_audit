use regex::Regex;

use super::zone;
extern crate unicase;

pub struct Root {
	pub zone : zone::Zone,
	pub root_addr : std::collections::hash_map::HashMap< unicase::Ascii<String>, Vec< zone::record::ZoneRecord > >,

	nameservers : std::collections::hash_map::HashMap::<unicase::Ascii<String>, Vec< zone::record::ZoneRecord >>,
	addresses : std::collections::hash_map::HashMap::<unicase::Ascii<String>, Vec< zone::record::ZoneRecord >>

}

impl Root {

	pub fn create( file_name : &String, origin : &String )  -> Result< Self, String > {

		let mut rval = Root {
			zone: match zone::Zone::create(&file_name, &origin)  {
				Ok(m) => { m },
				Err(e) => { return Err(e) }
			},
			root_addr: std::collections::hash_map::HashMap::new(),
			nameservers: std::collections::hash_map::HashMap::new(),
			addresses: std::collections::hash_map::HashMap::new(),
		};

		rval.from_file()?;

		Ok(rval)
	}

	pub fn from_file<'a>( &'a mut self) -> Result< (), String > {

		for record in &mut self.zone.records {

			let zone_record = record.as_any().downcast_mut::<zone::record::ZoneRecord>();
			match zone_record {
				Some(rec) => {

					if rec.record_type == zone::record::RecordType::NS {
						self.nameservers.entry(unicase::Ascii::new(rec.name.fqdn.clone())).or_insert_with( || Vec::new() ).push( rec.clone() );
					} else if rec.record_type == zone::record::RecordType::A || rec.record_type == zone::record::RecordType::AAAA {
						self.addresses.entry(unicase::Ascii::new(rec.name.fqdn.clone())).or_insert_with(|| Vec::new()).push( rec.clone() );			
					}
				},
				None => {}
			}
		}

		for (zone_name, zone_record) in &mut self.nameservers {

			for server in zone_record.iter_mut() {
				if let Some(rdata) = &mut server.rdata {
					if let Some(ns_rr) = rdata.as_mut().as_any_mut().downcast_mut::<zone::rr::RDATANameRR>() {
						if let Some(i) = self.addresses.get_mut( &unicase::Ascii::new(ns_rr.name.fqdn.clone()) ) {
							self.root_addr.entry(zone_name.clone()).or_insert_with(|| Vec::new()).append( &mut i.clone() );
						}
					}
				}
			}
		}

		Ok(())
	}

	pub fn split_name( domain_name : &String ) -> Vec<String> {

		let delim = Regex::new(r"(([^\\])|(^))\.").unwrap();

		let spl = delim.split( &domain_name );
		
		let mut rval = Vec::<String>::new();

		for n in spl {
			let mut str = n.to_string();
			str.push('.');
			rval.push( str );
		}

		return rval;
	}

	fn _get_nameservers(&self, name_split : &Vec<String>, zone_name : &mut String ) -> Result<&Vec< zone::record::ZoneRecord >, String> {

		let mut last_ns : Option< &Vec<zone::record::ZoneRecord > > = None;
		

		for zn in name_split.iter().rev() {
			let mut _zone_name = zn.clone();
			_zone_name.push_str(zone_name.as_str());

			let _zone_ascii = unicase::Ascii::new( _zone_name );

			if let Some(ns) = self.root_addr.get(&_zone_ascii) {
				last_ns = Some(ns);
				zone_name.clone_from(&_zone_ascii.to_string());
			} else { break; }
		}

		if let Some(n) = last_ns {
			return Ok(&n);
		}

		Err(format!("Did not find the zone '{}'", zone_name).to_string())

	}

	pub fn get_nameservers(&self, domain_name : &String) -> Result<&Vec< zone::record::ZoneRecord >, String> {

		let spl = Self::split_name(domain_name);
		let mut zone_name : String = String::new();
		self._get_nameservers( &spl, &mut zone_name )
	}

	/*
	 This function works more or less like get_
	 */
	pub fn get_nameservers_and_resolve(&self, domain_name : &String) -> Result<&Vec< zone::record::ZoneRecord >, String> {

		let mut last_ns : Option< &Vec<zone::record::ZoneRecord > > = None;
		let mut zone_name : String = String::new();

		let spl = Self::split_name(domain_name);

		for zn in spl.iter().rev() {
			let mut _zone_name = zn.clone();
			_zone_name.push_str(zone_name.as_str());

			let _zone_ascii = unicase::Ascii::new( _zone_name );

			if let Some(ns) = self.root_addr.get(&_zone_ascii) {
				last_ns = Some(ns);
				zone_name = _zone_ascii.to_string();
			} else { break; }
		}

		if let Some(n) = last_ns {
			return Ok(&n);
		}

		Err("nameserver not found".to_string())
	}

}

impl std::fmt::Display for Root {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		
		for (zone_name, records) in &self.root_addr {
			write!(f, "\nZone: '{}'", zone_name)?;

			for rec in records {
				if let Some(ip) = &rec.rdata {
					write!(f, "\n\t{}", ip)?;
				}
			}
		}
		        
		Ok(())
    }
}