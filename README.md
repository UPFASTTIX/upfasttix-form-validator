# 🔒 upfasttix-form-validator  
**AI-Powered, Ultra-Secure Form Validation**  

[![npm version](https://img.shields.io/npm/v/upfasttix-form-validator.svg?color=blue&style=for-the-badge)](https://www.npmjs.com/package/upfasttix-form-validator)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
![Security](https://img.shields.io/badge/Security-Military%20Grade-red?style=for-the-badge)
![Node.js](https://img.shields.io/badge/Node.js-18+-yellow?style=for-the-badge)

---


> **upfasttix-form-validator** is a **military-grade form validation library** for Node.js and JavaScript.  
> It automatically detects and validates **Email, Phone, Password, Date of Birth (18+)**, and **Name** with **enterprise-grade security & privacy checks**.  

---

## 🚀 Features
✅ AI-inspired detection – Automatically detects common fields  
✅ Strong password validation (entropy, symbols, case, numbers)  
✅ Strong email & phone validation (international + regex)  
✅ DOB validation with age check (18+ supported)  
✅ Name validation with pattern checks  
✅ Optional fields – If added, validation is enforced  
✅ Timing-safe password comparison  
✅ Lightweight, privacy-first, and blazing fast  

---

## 📦 Installation

```bash
npm install upfasttix-form-validator
```

Or for local development:  

```bash
git clone <repo-url>
cd upfasttix-form-validator
npm link
```

---

## 🧪 Usage

```javascript
const { validate } = require("upfasttix-form-validator");

(async () => {
  const form = {
    name: "Jonn Dev",
    email: "test@example.com",
    phone: "+911234567890",
    dob: "2025-08-1",
    password: "StrongPass@1234",
    confirmPassword: "StrongPass@1234"
  };

  const result = await validate(form, { minAge: 18 });

  console.log(JSON.stringify(result, null, 2));
})();
```

---

## 📝 Example Output

```json
{
  "valid": true,
  "errors": {},
  "cleaned": {
    "name": "Jonn Dev",
    "email": "test@example.com",
    "phone": "+911234567890",
    "dob": "2025-08-1",
    "passwordValidated": true,
    "confirmPassword": true
  },
  "meta": {
    "validatedAt": "2025-08-31T10:00:00.000Z",
    "fieldsValidated": [
      { "key": "name", "detected": "name" },
      { "key": "email", "detected": "email" },
      { "key": "phone", "detected": "phone" },
      { "key": "dob", "detected": "dob" },
      { "key": "password", "detected": "password" },
      { "key": "confirmPassword", "detected": "confirmPassword" }
    ]
  }
}
```

---

## ⚙️ Options

| Option     | Type    | Default | Description                               |
|------------|--------|---------|-------------------------------------------|
| `minAge`   | number | `18`    | Minimum age requirement for DOB validation|

---

## 🔐 Security
- Constant-time password comparisons  
- Entropy scoring for strong passwords  
- Regex + RFC-compliant validation  
- Input sanitization to prevent injection attacks  

---

## 🛠 Development Setup

```bash
# Clone the project
git clone https://github.com/UPFASTTIX/upfasttix-form-validator.git
cd upfasttix-form-validator

# Install dependencies
npm install

# Link locally
npm link

# Test in another project
mkdir test-upfasttix
cd test-upfasttix
npm init -y
npm link upfasttix-form-validator
```

---

## 📜 License
MIT © 2025 UPFASTTIX

---

🔥 Built with ❤️ by upfasttix-form-validator – Making Validation Military Grade 🔒  

