# SecretRadar

**A browser extension for real-time, client-side secret scanning.**

SecretRadar is an essential security tool for developers, pentesters, and security auditors, designed to proactively uncover leaked secrets and misconfigurations directly in your browser. Think of it as Gitleaks or Trufflehog, but purpose-built for the client-side analysis of live web applications.

It automatically scans web pages, loaded scripts, and network traffic for accidentally exposed API keys, authentication tokens, private keys, and other sensitive data, helping you stop client-side data leaks before they become a serious threat.

## Installation

You can install the extension from the official Chrome Web Store.

**[Install SecretRadar from the Chrome Web Store]** *(<-- Вставьте сюда вашу ссылку)*

## Key Features

-   **High-Fidelity Detection**: Goes beyond simple regex. Our engine uses context-aware scanning to provide high-accuracy findings and minimize false positives, letting you focus on real threats.

-   **Optimized Performance**: Built for speed. Asynchronous scanning and intelligent debounce mechanisms ensure your Browse experience remains fast and smooth with a minimal performance footprint.

-   **Full Control & Flexibility**: Customize the engine to your workflow. Adjust confidence thresholds to fine-tune sensitivity and use the powerful deny-list system to exclude trusted domains and patterns.

-   **Actionable Analytics Dashboard**: All findings are presented in a clean, centralized dashboard. Filter, sort, and inspect discovered secrets with detailed context. Export your results to JSON or CSV for reporting or further analysis.

## What SecretRadar Finds

SecretRadar is capable of detecting a wide range of sensitive data, including:

-   **API Keys**: AWS, GitHub, GitLab, Slack, Stripe, Heroku, Mailgun, and more.
-   **Cryptographic Keys**: RSA, DSA, EC, & PGP private keys.
-   **Authentication Tokens**: JWT (JSON Web Tokens).
-   **Configuration Files**: Exposed `.env` files and other sensitive data within source code.

## Who Is It For?

-   **Developers**: Audit your own applications during development to catch leaks before they hit production.
-   **Pentesters & Bug Bounty Hunters**: A powerful tool for client-side reconnaissance and identifying low-hanging fruit.
-   **Security Auditors**: Analyze web applications for common security flaws and misconfigurations.

## Privacy by Design

Your privacy is paramount. SecretRadar operates entirely locally on your machine. All scanning and analysis happens within your browser, and no data — including the secrets you find — is ever transmitted or stored outside of your local device.


## License

This project is licensed under the [WTFPL license](LICENSE).
