# Secure Password-Manager

A secure and feature-rich password manager built with Python and PyQt5.

## Features

### Password Management
- Generate strong random passwords
- Save passwords with categories and titles 
- Retrieve passwords securely
- Update existing passwords
- List all stored passwords in an organized view
- Delete passwords
- Import/Export password data

### Security
- Strong encryption using Fernet (symmetric encryption)
- Master password protection with bcrypt hashing
- Two-factor authentication (2FA) support using TOTP
- Password strength checker
- Breached password detection using haveibeenpwned API
- Security audit functionality
- Automatic clipboard clearing
- Audit logging

### User Interface
- Modern and intuitive GUI using PyQt5
- Dark/Light theme toggle
- System tray integration
- Tabbed interface for organized features
- Secure password visibility

## Technical Details

### Dependencies
- Python 3.6+
- PyQt5
- cryptography
- bcrypt
- pyotp
- qrcode
- requests

### Security Implementation
- PBKDF2 key derivation
- Bcrypt password hashing
- Fernet symmetric encryption
- TOTP-based 2FA
- Secure password generation
- Automatic data encryption

### File Structure
- `DB/passwords.encrypted`: Encrypted password storage
- `DB/users.json`: User account information
- `DB/mfa_secrets.json`: 2FA secrets
- `DB/audit_log.json`: Security audit logs
- `DB/salt.key`: Encryption salt
- `DB/key.key`: Encryption key

## Usage

1. Run the application
2. Create a new user account or login
3. Set up 2FA (optional but recommended)
4. Use the tabbed interface to:
   - Manage passwords
   - Perform security operations
   - Configure settings

## Security Best Practices
- Use a strong master password
- Enable 2FA
- Regularly perform security audits
- Update passwords periodically
- Keep the software updated
- Don't share your master password
- Regularly check for breached passwords

## Contributing
Contributions are welcome! Please feel free to submit pull requests.

## License
This project is licensed under the MIT License.
