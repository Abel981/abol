# ☕ Contributing to Abol

First off, thank you for considering contributing to **Abol**!\
It's people like you that make the Rust ecosystem such a great place to
build reliable, high-performance software.

This guide follows best practices established by projects like
**tokio**, **serde**, and **rust-analyzer**.

------------------------------------------------------------------------

## 📑 Table of Contents

-   [Code of Conduct](#-code-of-conduct)
-   [How Can I Contribute?](#-how-can-i-contribute)
    -   [Reporting Bugs](#reporting-bugs)
    -   [Suggesting Enhancements](#suggesting-enhancements)
    -   [Submitting Pull Requests](#submitting-pull-requests)
-   [Development Environment](#-development-environment)
-   [Pull Request Process](#-pull-request-process)
-   [Coding Style](#-coding-style)

------------------------------------------------------------------------

## 🤝 Code of Conduct

By participating in this project, you agree to abide by the **[Rust Code
of Conduct](https://www.rust-lang.org/policies/code-of-conduct)**.

We are committed to providing a **friendly, safe, and welcoming
environment** for everyone.

------------------------------------------------------------------------

## 🛠 How Can I Contribute?

### 🐞 Reporting Bugs

Before reporting a bug:

-   Check the **issue tracker** to see if it has already been reported.

If it hasn't:

-   Open a new issue
-   Provide a **clear title**
-   Describe the problem in detail
-   Include **steps to reproduce**
-   A **minimal reproducible example** is highly appreciated

------------------------------------------------------------------------

### 💡 Suggesting Enhancements

-   Open an issue with the **`enhancement`** label
-   Clearly explain the **motivation**
-   Describe how the feature benefits the **RADIUS community**
-   Include references to RFCs when applicable

------------------------------------------------------------------------

### 🔧 Submitting Pull Requests

-   **Small fixes**\
    You're welcome to submit a PR directly.

-   **Large features**\
    Please open an issue for discussion first to ensure alignment with
    the project roadmap.

------------------------------------------------------------------------

## 🧰 Development Environment

### Fork and Clone

``` bash
git clone https://github.com/youruser/abol.git
cd abol
```

### Verify Setup

``` bash
cargo test
```

### Code Generation Requirements

Since Abol uses build-time code generation, ensure `rustfmt` is
installed so generated traits remain readable:

``` bash
rustup component add rustfmt
```

------------------------------------------------------------------------

## 🔁 Pull Request Process

1.  Create a new branch:

    ``` bash
    git checkout -b feature/my-new-feature
    ```

2.  Implement your changes and add tests where appropriate

3.  Run the full quality gate:

    ``` bash
    cargo fmt --all -- --check
    cargo clippy -- -D warnings
    cargo test
    ```

4.  Update `README.md` or documentation if public APIs changed

5.  Open the Pull Request and wait for review 🚀

------------------------------------------------------------------------

## 🧹 Coding Style

-   🦀 **Idiomatic Rust**\
    Follow the [Rust API
    Guidelines](https://rust-lang.github.io/api-guidelines/)

-   📚 **Documentation**\
    All public modules, structs, and functions must have doc comments
    (`///`)\
    Include examples where possible

-   🔐 **Safety**\
    Avoid `unsafe` unless strictly necessary\
    If used, clearly document safety invariants

-   ⚠️ **Error Handling**

    -   Use `thiserror` for library-internal errors
    -   Use `anyhow` for application-level or server logic

------------------------------------------------------------------------


<p align="center">
```
☕ `<b>`{=html}Happy Brewing!`</b>`{=html}`<br/>`{=html} If you have
questions, feel free to reach out via GitHub issues.

</p>
```
