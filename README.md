# Secure Password Manager

This project implements a secure and efficient password manager in JavaScript, designed to safely store and manage passwords using cryptographic techniques. The core library includes various functions that enable password encryption, integrity checking, and secure storage of domain-password pairs. 

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [API Methods](#api-methods)
- [Security](#security)
- [Testing](#testing)
- [Contributing](#contributing)

## Features

- **Password Encryption**: AES-GCM encryption for secure storage of passwords.
- **Domain Name Obfuscation**: HMAC is used to hide domain names while enabling lookup.
- **Password Integrity Checks**: A SHA-256 checksum protects against tampering and rollback attacks.
- **PBKDF2 Key Derivation**: Strengthened key derivation for secure master password handling.

## Technologies Used

- **JavaScript**
- **Node.js** with the `crypto` library for cryptographic functions
- **MochaJS** for testing
- **Expect.js** for assertions in test cases

## Getting Started

### Prerequisites

- **Node.js** (Download from [nodejs.org](https://nodejs.org/en/download/))

### Installation

1. **Clone the Repository**
    ```bash
    git clone <repository-url>
    cd proj1
    ```

2. **Install Dependencies**
    ```bash
    npm install
    ```

### Running the Tests

To test the implementation, run:
```bash
npm test
