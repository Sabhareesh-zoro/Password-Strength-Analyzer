# 🔐 Password Strength Analyzer

A modern React-based Password Strength Analyzer that evaluates password security in real time and provides actionable recommendations for creating stronger passwords.

## 🚀 Features

- ✅ Real-time password strength analysis
- 🔒 Password entropy calculation
- 📏 Password length validation
- 🔠 Uppercase and lowercase letter detection
- 🔢 Number detection
- 🔣 Special character detection
- 🚫 Detection of common/breached passwords
- ⌨️ Keyboard pattern detection (e.g., qwerty, asdf)
- 🔄 Sequential character detection (e.g., abc, 123)
- 📊 Password strength score (0–100)
- 💡 Personalized suggestions for stronger passwords
- 🎲 Secure random password generator
- 📝 Memorable passphrase generator
- 📋 One-click copy to clipboard
- 🔐 SHA-256 password hashing (for demonstration)
- 🕒 Password history and reuse detection
- 📱 Responsive and modern user interface

---

## 🛠️ Technologies Used

- React (JSX)
- JavaScript (ES6+)
- HTML5
- Tailwind CSS
- Lucide React Icons
- Web Crypto API (SHA-256)

---

## 📷 Preview

> Add screenshots of your application here.

Example:

- Home Screen
- Password Analysis
- Password Generator
- Password History

---

## 📂 Project Structure

```
Password-Strength-Analyzer/
│
├── PasswordStrengthAnalyzer.jsx
├── README.md
└── assets/
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Password-Strength-Analyzer.git
```

Go to the project folder:

```bash
cd Password-Strength-Analyzer
```

Install dependencies:

```bash
npm install
```

Run the application:

```bash
npm run dev
```

---

## 📌 How It Works

The application evaluates passwords based on multiple security parameters including:

- Password length
- Character variety
- Password entropy
- Common password detection
- Keyboard pattern detection
- Sequential character detection
- Character repetition
- Password reuse detection

It then calculates a security score and classifies the password as:

- Very Weak
- Weak
- Fair
- Strong
- Very Strong

---

## 🔒 Security Note

This project is intended for educational and demonstration purposes.

The password history feature uses SHA-256 hashing within the browser to simulate password reuse detection.

In production systems, passwords should always be protected using slow, salted hashing algorithms such as:

- bcrypt
- scrypt
- Argon2

---

## 🎯 Learning Outcomes

This project helped me understand:

- Password security best practices
- Password entropy
- Cryptographic hashing
- Secure password generation
- React Hooks
- State Management
- Responsive UI Design
- Secure coding principles

---

## 👨‍💻 Author

**Sabhareesh U S**

LinkedIn: https://www.linkedin.com/in/YOUR-LINKEDIN

GitHub: https://github.com/YOUR_GITHUB_USERNAME

---

## ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub.
