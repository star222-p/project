# Web Application Security Scanner

A tool to scan web applications for various security vulnerabilities. It identifies vulnerabilities such as XSS, SQL Injection, SSRF, CSRF, and more, and suggests remediation steps.

## Features

- **Vulnerability Detection**: Detects common vulnerabilities in web applications such as:
  - Cross Site Scripting (XSS)
  - SQL Injection
  - Open Redirection
  - Server-Side Request Forgery (SSRF)
  - Cross-Site Request Forgery (CSRF)
  - Cross-Origin Resource Sharing (CORS) misconfigurations
  - Path Traversal
  - Remote Code Execution (RCE)
  - Clickjacking
  - Broken Access Control
  - Sensitive Information Disclosure
  - Unrestricted File Upload, and more.

- **Payload Customization**: Use predefined or custom payloads to test for vulnerabilities.

- **Multi-threaded Scanning**: Perform scans with multiple threads for faster results.

- **Nuclei Template Support**: Run custom Nuclei templates for more advanced vulnerability detection.

## Installation

You can install the tool from GitHub or by using `pip`.

