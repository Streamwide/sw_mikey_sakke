# Modifications to Open Source Components

This document describes the modifications applied by **Streamwide S.A.** to certain open source components included in the **Streamwide SDK**.

---

### 1. sw_mikey_sakke (LGPL-2.1-or-later)
- **Base:** Derived from `libmikey-sakke` and `minisip-mikey-sakke`.
- **Modifications by Streamwide S.A.:**
  - Adapted build system for iOS dynamic framework compatibility.
  - Integrated with internal cryptographic handling for secure key exchange.
  - Minor bug fixes for memory management.
  - No functional changes to original cryptographic logic.

---

### 2. openssl (Apache 2.0 / OpenSSL)
- **No code modification**
- Use only of module **ssl** & **crypto**
- `sw_ssl` & `sw_crypto` are only prefixed by 'sw' because the iOS framework is made by Streamwide.

## Compliance Note

All modified components retain their original license headers and copyright notices.
Each modification has been documented and preserved in version control.

No change affects license scope or redistribution rights.

© 2025 Streamwide S.A.

