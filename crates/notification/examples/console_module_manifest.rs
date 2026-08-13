use std::io::{self, Write as _};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = notification::module::manifest().console_module_manifest("^2.1.0", "^2.0.0");
    let mut output = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer_pretty(&mut output, &manifest)?;
    writeln!(output)?;
    Ok(())
}
