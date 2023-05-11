pub mod zone_tokenizer;

fn main() {
    let tokens = zone_tokenizer::tokenize_zone_file("root.zone");
}
