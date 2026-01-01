Contributing to Abol ☕

First off, thank you for considering contributing to Abol! It's people like you that make the Rust ecosystem such a great place to build reliable software.

This guide follows the best practices established by projects like tokio, serde, and rust-analyzer.

Table of Contents

Code of Conduct

How Can I Contribute?

Development Environment

Pull Request Process

Coding Style

Code of Conduct

By participating in this project, you agree to abide by the Rust Code of Conduct. We are committed to providing a friendly, safe, and welcoming environment for all.

How Can I Contribute?

Reporting Bugs

Check the issue tracker to see if the bug has already been reported.

If not, open a new issue. Include a clear title, a description of the problem, and steps to reproduce (a minimal reproducible example is highly appreciated).

Suggesting Enhancements

Open an issue with the "enhancement" label.

Explain the "why" behind the feature. How does it benefit the RADIUS community?

Submitting Pull Requests

Small fixes: Feel free to submit a PR directly.

Large features: Please open an issue for discussion before putting in significant work. This ensures your efforts align with the project's roadmap.

Development Environment

To get started with the codebase:

Fork and Clone:

git clone [https://github.com/youruser/abol.git](https://github.com/youruser/abol.git)
cd abol


Verify Setup:

cargo test


Code Generation:
Since Abol uses a code generator, ensure you have rustfmt installed so the generated traits are readable:

rustup component add rustfmt


Pull Request Process

Create a new branch for your feature/fix: git checkout -b feature/my-new-feature.

Write your code and add tests for any new functionality.

Run the following suite to ensure everything is perfect:

cargo fmt --all -- --check

cargo clippy -- -D warnings

cargo test

Update the README.md or documentation if you've changed public APIs.

Submit the PR and wait for a review!

Coding Style

Idiomatic Rust: We follow the Rust API Guidelines.

Documentation: All public modules, structs, and methods should have doc comments (///). Use examples where possible.

Safety: Avoid unsafe unless strictly necessary for performance. If used, document the safety invariants.

Error Handling: Prefer thiserror for library-internal errors and anyhow for application-level server logic.

Happy Brewing! If you have questions, feel free to reach out via GitHub issues.