
pub mod record;
pub mod tokenizer;

pub struct Zone {
	pub records: std::collections::HashMap<String, Vec<record::ZoneRecord> >
}

impl Zone {

	pub fn create( filename : & String ) -> Result<Zone, String> { 

		let mut zone: Zone = Default::default();

		let mut token_lines = tokenizer::ZoneLines::create(filename)?;

		for line in token_lines.lines {

			match record::ZoneRecord::create(&line) {
				Err(e) => { return Err(e); },
				Ok(m) => { 
					zone.records.entry(m.name.clone()).or_default().push( m ); 
				}
			}
		}

		return Ok(zone);
	}

}

impl Default for Zone {
	fn default() -> Self {
		Zone {
			records: std::collections::HashMap::new()
		}
	}
}