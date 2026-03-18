# Contributing to bVault-js

First off, thank you for checking out **bVault-js**\! We are building the fastest, most secure frontend encryption layer for the modern web. Whether you are fixing a bug, improving performance, or helping us bridge the gap to hardware-backed security, your contribution is valued.

As a project under **OSSAfrica**, we maintain high standards for cryptographic integrity and execution speed.

-----

## Security First

**If you find a security vulnerability, please DO NOT open a public issue.**
Because bVault-js handles sensitive data, we follow a strict responsible disclosure policy. Please review our [SECURITY.md](SECURITY.md) to report vulnerabilities privately to our security team.

-----

## The "Fast-Track" Workflow

We move fast, and we want our contributors to move fast too. To maintain a high velocity while ensuring code quality, we follow this specific 4-step process:

1.  **Create an Issue:** Start by opening an [Issue](https://github.com/OSSAfrica/bvault-js/issues). Describe exactly what you want to add or fix.
2.  **Describe the Gain:** In the issue, explain the "Why." Are you improving security? Increasing encryption speed? Reducing bundle size?
3.  **Create a Pull Request:** Once a maintainer gives the go-ahead, fork the repo, create a branch, and submit your PR.
4.  **Push & Iterate:** We aim for rapid review cycles. Be prepared to iterate quickly based on feedback from the core staff.

-----

## Current Priority: The WebAuthn & Speed Sprint

We are currently fast-tracking the implementation of **Hardware-Bound Security**. We are looking for "Sprint Staff"—contributors who want to work closely with us on:

  * **WebAuthn PRF Integration:** Offloading key derivation from the CPU to the device's hardware (Windows Hello / Android Biometrics).
  * **Performance Optimization:** Reducing the "Crypto Tax" to ensure sub-millisecond encryption/decryption cycles.
  * **Metadata Vaulting:** Moving Salts and IVs from software storage (`IndexedDB`) to hardware-attested storage.

**If you have experience with Web Crypto or WebAuthn, mention "Sprint Staff" in your issue to get prioritized\!**

-----

## Development Setup

Get up and running in seconds:

```bash
# 1. Clone your fork
git clone https://github.com/OSSAfrica/bvault-js.git

# 2. Install dependencies (Zero-dependency goal!)
npm install

# 3. Run the performance benchmarks & tests
npm test
```

### Technical Requirements

  * **TypeScript:** All code must be strictly typed.
  * **Zero Dependencies:** We do not accept PRs that add external production dependencies. We use the native browser APIs (Web Crypto, WebAuthn) for maximum speed and security.
  * **Performance-Minded:** If a change slows down the library, it must be justified by a significant security gain.

-----

## Code of Conduct

By participating in this project, you agree to abide by the **OSSAfrica Code of Conduct**. We value a community that is inclusive, respectful, and focused on building great technology for everyone.

## License

By contributing to bVault-js, you agree that your contributions will be licensed under the project's **MIT License**.

-----

**Ready to build the future of web security? [Open an issue](https://github.com/ossafrica/bvault-js/issues) and let's get to work.**
