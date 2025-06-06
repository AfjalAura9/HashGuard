# 🛡️ HashGuard - Realtime Malware scanning, File integrity check, URL Reputation check [Live demo](https://hashguard.onrender.com)

  HashGuard is a web application designed for comprehensive file and URL safety analysis. It empowers users to verify file integrity, scan for malware, and check the reputation of URLs—all from one secure, user-friendly dashboard.
  Whether you're uploading critical documents or browsing untrusted links, HashGuard keeps you safe with robust scanning and verification mechanisms.

---

## 🚀 Features

- 🔐 User Authentication (Register, Login, Logout)
- 🧪 Malware Scanning via [VirusTotal API](https://www.virustotal.com/)
- 📁 File Integrity Verification using Cryptographic Hashing (SHA-256)
- 🔗 URL Reputation Analysis
- 📊 Scan Reports & Integrity Reports generatiion
- 📱 Responsive UI (Built with Bootstrap 5)

---

## 🛠️ Technologies Used

| Layer         | Tech Stack                                 |
|---------------|---------------------------------------------|
| Language      | Python 3                                    |
| Framework     | Django                                      |
| Frontend      | HTML5, CSS3, JavaScript, Bootstrap 5        |
| Database      | PostgreSQL                                  |
| Security APIs | VirusTotal API                              |
| DevOps        | Git, GitHub                                 |

---

## 📁 Project Structure
## ⚙️ Setup & Installation

1. **Clone the Repository**
```bash
git clone https://github.com/AfjalAura9/HashGuard.git
cd HashGuard
```
2. **Create and Activate a Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```
3. **Install Dependencies**
```bash
pip install -r requirements.txt
```
4. Configure Environment Variables
```bash
Add your VirusTotal API Key in a .env or settings file.
Set up PostgreSQL DB credentials.
```
5. **Apply Migrations**
```bash
python manage.py migrate
```
6. **Run the Development Server**
```bash
python manage.py runserver
```
7. **Access the App**
```bash
http://127.0.0.1:8000/
```

## 🧪 How to Use
🦠 Malware Scanning
Uploaded files are scanned using the VirusTotal API.

📁 File Integrity Check
SHA-256 hash will be generated and stored.

🔗 URL Reputation Check
Paste any URL to check its trustworthiness via VirusTotal.

📊 Dashboard
View recent file scans, malware checks, and URL reports.

## 📸 Screenshots
![Home](static/images/home.png)

#### 📊 Dashboard
![Dashboard](static/images/dashboard.png)

#### 🧾 Scan Report
![Report](static/images/report.png)

# 🤝 Contributing
We welcome contributions!

🛠 Steps
Fork the repo

Create a new branch:
```bash
git checkout -b feature/AmazingFeature
```

Commit your changes:
```bash
git commit -m "Add AmazingFeature"
```

Push and submit a PR:
```bash
git push origin feature/AmazingFeature
```

## 📄 License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.

---

## 👥 Authors

- **Afjal Shaik** – Full-stack Developer  
- **Somesh Jyothula** – Backend & VirusTotal Integration  
- **Tabres Ahamed** – Research & Documentation

---

## 📬 Contact

For bugs, feature requests, or collaborations:

- Open an [Issue](https://github.com/AfjalAura9/HashGuard/issues)
- Reach out via the GitHub profiles listed above

---

## 🙏 Acknowledgements

- [Django Project](https://www.djangoproject.com/)
- [VirusTotal](https://www.virustotal.com/)
- [Bootstrap](https://getbootstrap.com/)
- [PostgreSQL](https://www.postgresql.org/)
