# 🔐 PKCS#11-Based Cryptographic Service in C

This project implements a modular and extensible cryptographic service using the [PKCS#11 (Cryptoki)](https://docs.oasis-open.org/pkcs11/pkcs11-base/) standard. It is built in C and designed using the **SOLID principles** of software design.

---

## 📌 Features

- 🔑 AES encryption and decryption using SoftHSM-backed PKCS#11 keys
- 🧩 Extensible to support other algorithms (e.g., RSA, ECC, ChaCha20)
- ✅ Designed with SOLID principles for clean architecture and maintainability
- 🔄 Pluggable architecture via interfaces and dynamic dispatch
- 📚 Clean separation of concerns: key management, encryption logic, PKCS#11 API handling

---

## 📁 Project Structure
```bash
pkcs11encryptdecrypt/
├── include/ # Header files (interfaces & data structures)
│ ├── encryption_service.h
│ ├── key_manager.h
│ └── pkcs11_wrapper.h
├── src/ # Source files
│ ├── aes_encryption_service.c
│ ├── key_manager.c
│ └── pkcs11_wrapper.c
├── main.c # Demo client
├── Makefile
└── README.md
```
---

## 🔧 Prerequisites

- GCC or Clang
- [`libsofthsm2`](https://github.com/opendnssec/SoftHSMv2) installed
- SoftHSM configured with at least one token
- Development headers for PKCS#11 (`libpkcs11-dev` on some systems)

### 🔐 SoftHSM Setup (Example)

```bash
softhsm2-util --init-token --slot 0 --label "MyToken"
# PIN: 12345678
```

## ⚙️ Building the Project

```bash
make
```

## 🚀 Usage

```bash
./pkcs11encryptdecrypt
```

## SOLID PRINCIPLE APPLIED

| Principle | Description                                                                         |
| --------- | ----------------------------------------------------------------------------------- |
| **SRP**   | Each module handles a single responsibility (e.g., AES service, key manager).       |
| **OCP**   | New algorithms can be added via new modules without modifying existing code.        |
| **LSP**   | All services adhere to a shared `EncryptionService` interface.                      |
| **ISP**   | Only relevant interfaces are exposed (e.g., `encrypt`, `decrypt`).                  |
| **DIP**   | High-level code depends on abstractions (`EncryptionService`), not implementations. |
