use abol_codegen::Generator;
use abol_parser::{FileOpener, dictionary::Dictionary};
use anyhow::{Context, Result};
use clap::Parser;
use std::{fs, path::PathBuf};

#[derive(Parser)]
struct Args {
    /// Input dictionary files (multiple files can be provided)
    #[arg(short, long, required = true)]
    inputs: Vec<PathBuf>,

    /// Output filename or directory
    #[arg(short, long)]
    output: PathBuf,

    /// Module name for the generated code
    #[arg(short, long, default_value = "radius_core")]
    name: String,

    /// If set, identical attribute definitions across files won't cause an error
    #[arg(long, default_value_t = false)]
    ignore_identical_attributes: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut final_dict = Dictionary::default();

    for input_path in &args.inputs {
        let root = input_path.parent().context(format!(
            "Could not determine parent directory of {:?}",
            input_path
        ))?;

        let file_name = input_path
            .file_name()
            .context(format!("Could not determine filename of {:?}", input_path))?;

        // Create a parser for this specific file's context
        let file_opener = FileOpener::new(root);
        let parser = abol_parser::Parser::new(file_opener, args.ignore_identical_attributes);

        println!("Parsing {:?}...", input_path);

        // 2. Parse the individual file
        let next_dict = parser
            .parse_dictionary(file_name)
            .with_context(|| format!("Failed to parse dictionary file {:?}", input_path))?;

        // 3. Merge into the accumulator (this runs our validation logic)
        final_dict = Dictionary::merge(&final_dict, &next_dict)
            .map_err(|e| anyhow::anyhow!("Merge conflict in {:?}: {}", input_path, e))?;
    }

    // 4. Generate the code from the consolidated dictionary
    let generator = Generator::new(&args.name);
    let code = generator
        .generate(&final_dict)
        .map_err(|e| anyhow::anyhow!("Code generation failed: {}", e))?;

    // 5. Determine output path
    let mut final_output_path = args.output;
    if final_output_path.is_dir() {
        let final_name = format!("{}.rs", args.name.to_lowercase());
        final_output_path.push(final_name);
    }

    // 6. Ensure directory exists and write
    if let Some(parent) = final_output_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create directories for output file {:?}",
                final_output_path
            )
        })?;
    }

    fs::write(&final_output_path, code)
        .with_context(|| format!("Failed to write output file {:?}", final_output_path))?;

    println!(
        "Successfully merged {} files and generated Rust code at {:?}",
        args.inputs.len(),
        final_output_path
    );

    Ok(())
}
