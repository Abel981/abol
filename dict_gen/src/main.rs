use clap::Parser;
use dict_gen::Generator;
use dict_parser::FileOpener;
use std::{fs, path::PathBuf};

use anyhow::{Context, Result};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    input: PathBuf,
    #[arg(short, long, default_value = "rfc2865")]
    standard: String,
    #[arg(short, long)]
    output: PathBuf,
    #[arg(short, long, default_value = "radius_core")]
    name: String,
    #[arg(long, default_value_t = false)]
    ignore_identical_attributes: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = args
        .input
        .parent()
        .context("Could not determine parent directory of input file")?;
    let file_name = args
        .input
        .file_name()
        .context("Could not determine filename")?;
    let file_opener = FileOpener::new(root);
    let parser = dict_parser::Parser::new(file_opener, args.ignore_identical_attributes);

    let dict = parser
        .parse_dictionary(file_name)
        .with_context(|| format!("Failed to parse dictionary file {:?}", args.input))?;
    let generator = Generator::new(&args.name);
    let code = generator
        .generate(&dict)
        .map_err(|e| anyhow::anyhow!("Generation failed: {}", e))?;
    let mut final_output = args.output;
    if final_output.is_dir() {
        let final_name = format!("{}.rs", args.name.to_lowercase());
        final_output.push(final_name);
    }
    if let Some(parent) = final_output.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create directories for output file {:?}",
                final_output
            )
        })?;
    }

    fs::write(&final_output, code)
        .with_context(|| format!("Failed to write output file {:?}", final_output))?;
    println!("Successfully generated Rust code at {:?}", final_output);
    Ok(())
}
