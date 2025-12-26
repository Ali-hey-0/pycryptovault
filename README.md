
# 🔐 CryptoVault Pro

A modern, secure, and user-friendly file encryption and decryption tool with a professional GUI.

---

## 🚀 Features

- **Military-grade encryption:** AES-256-GCM, ChaCha20-Poly1305, and Fernet
- **Password-based or key file encryption** (with secure PBKDF2-HMAC-SHA256)
- **Automatic algorithm detection** for key files and encrypted files
- **File compression** before encryption (optional)
- **Operation history tracking** (auto-cleared for privacy)
- **Secure file wipe** (multi-pass overwrite)
- **Hash calculator** (SHA256, SHA512, MD5)
- **Password generator** (customizable, strong)
- **Dark/light theme** with modern UI
- **Drag & drop, batch operations, and more**
- **No cloud, no telemetry, 100% local**

---

## 🖥️ Screenshots

> _Add your own screenshots here!_

---

## ⚡ Quick Start

1. **Install dependencies:**
   ```bash
   pip install cryptography tkinterdnd2
   ```
2. **Run the app:**
   ```bash
   python file_encryption_tool.py
   ```
3. **Encrypt/Decrypt files:**
   - Choose algorithm and key type (password or key file)
   - Add files (drag & drop or file dialog)
   - Click **Encrypt** or **Decrypt**

---

## 🔑 Key Management & Security

- **Key files** store the algorithm name for safe decryption
- **Password-based encryption** uses a random salt and 480,000 PBKDF2 iterations
- **Never lose your key or password!** Files cannot be recovered without them
- **Only files encrypted by this app can be decrypted by it**
- **Key files are never uploaded or sent anywhere**

---

## 🛡️ Best Practices

- Use strong, unique passwords (16+ chars, mix of types)
- Backup your key files in a safe place
- Test decryption before deleting originals
- Use the secure wipe tool for sensitive file deletion
- Never share your keys or passwords

---

## 📝 Example Workflow

1. **Generate a key** (or use a password)
2. **Encrypt files** (optionally compress)
3. **Save the key file** (keep it safe!)
4. **Decrypt files** by loading the correct key or entering the password

---

## ❓ FAQ

**Q: Can I decrypt files on another computer?**  
A: Yes, as long as you have the correct key file or password and the app.

**Q: What if I lose my key or password?**  
A: There is no recovery. This is by design for maximum security.

**Q: Can I use this for backups or cloud storage?**  
A: Yes! Encrypt before uploading to any cloud service.

**Q: Is my data ever sent to the internet?**  
A: Never. All operations are 100% local.

---

## 🛠️ Advanced Options

- **Batch encrypt/decrypt**: Add multiple files at once
- **Compression**: Enable for smaller encrypted files
- **Hash calculator**: Verify file integrity
- **Password generator**: Create strong passwords
- **Theme toggle**: Switch between dark and light modes

---

## 📦 Project Structure

```
CryptoVault Pro/
├── file_encryption_tool.py   # Main application
├── README.md                # This file
```

---

## 📚 Dependencies
- Python 3.8+
- cryptography
- tkinter (standard)
- tkinterdnd2 (for drag & drop, optional)

---

## 📜 License

MIT License

---

## 👤 Author

- Developed by WebVajhegan
- Contributions welcome!

---

## 🌟 Enjoy using CryptoVault Pro!

_Encrypt your files. Protect your privacy. Stay secure._
