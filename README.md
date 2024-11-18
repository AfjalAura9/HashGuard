# HashGuard - File Integrity Verification Tool

## Overview
**HashGuard** is a web-based tool for verifying the integrity of files through hash algorithms like **MD5**, **SHA-256**, and **SHA-512**. Whether you're a developer, system administrator, or just someone who wants to verify the authenticity of downloaded files, **HashGuard** makes it easy and secure.

### Key Features:
- **Upload Files** for integrity checking.
- **Calculate Hash Values** using multiple algorithms: **MD5**, **SHA-256**, **SHA-512**, etc.
- **View Hash Values** along with timestamps of the calculations.
- **Built with Django** and **Python** for an easy-to-setup, scalable solution.

## Demo
You can test the application locally by following the instructions below or use a live demo (if available).

## Table of Contents
1. [Features](#features)
2. [Getting Started](#getting-started)
3. [Usage](#usage)
4. [How It Works](#how-it-works)
5. [Contributing](#contributing)
6. [License](#license)

## Getting Started

### Prerequisites
To run this project locally, you'll need:
- **Python** (version 3.8 or higher)
- **Django** (and other dependencies that will be installed automatically)

### Installation Instructions

1. **Clone the repository** to your local machine:
    ```bash
    git clone https://github.com/AfjalAura9/HashGuard-File-Integrity-Verification-Tool.git
    ```

2. **Navigate to the project directory**:
    ```bash
    cd HashGuard-File-Integrity-Verification-Tool
    ```

3. **Create a virtual environment** (optional, but recommended for managing dependencies):
    ```bash
    python -m venv venv
    ```

4. **Activate the virtual environment**:
    - On **Windows**:
        ```bash
        venv\Scripts\activate
        ```
    - On **macOS/Linux**:
        ```bash
        source venv/bin/activate
        ```

5. **Install required dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

6. **Apply database migrations** (this step ensures that the database is set up correctly):
    ```bash
    python manage.py migrate
    ```

7. **Run the development server**:
    ```bash
    python manage.py runserver
    ```

8. **Visit the app in your browser** at [http://127.0.0.1:8000/](http://127.0.0.1:8000/).

---

## Usage

1. **Upload a File:**
   - Click the **"Upload File"** button on the home page.
   - Choose the file you want to check for integrity.

2. **Choose Hash Algorithm:**
   - Once the file is uploaded, select a hash algorithm (MD5, SHA-256, or SHA-512) from the dropdown.

3. **View the Hash Value:**
   - After clicking **"Calculate"**, the hash value for the file will be displayed on the page along with a timestamp.

4. **Verify File Integrity:**
   - Use the calculated hash to compare against the original file’s hash (from the file provider or official source).

---

## How It Works

The **HashGuard** uses cryptographic hash functions to calculate unique values for files, which are used to verify the integrity of the file. Hash functions like **MD5**, **SHA-256**, and **SHA-512** take input data (a file) and produce a fixed-size string that is unique to that data. Even small changes to the file will result in a completely different hash.

- **MD5**: Fast but less secure.
- **SHA-256**: Provides a good balance of speed and security.
- **SHA-512**: Stronger security but slower compared to SHA-256.

These algorithms are widely used for verifying file integrity, especially when downloading or sharing files from external sources.

---

## Contributing

Contributions are welcome! If you'd like to improve this project, feel free to fork the repository, make your changes, and submit a pull request.

### Steps to Contribute:
1. Fork this repository.
2. Create a new branch (`git checkout -b feature/your-feature-name`).
3. Make your changes and commit them (`git commit -am 'Add new feature'`).
4. Push to your branch (`git push origin feature/your-feature-name`).
5. Open a pull request describing your changes.

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgements
- **Django** for the powerful web framework.
- **Python** for making this project easy and flexible to implement.
- Any libraries or resources used in the project (e.g., `hashlib`).

---

## Contact

For any questions or inquiries, feel free to reach out to me on GitHub or via email: [afjalshaik@example.com](mailto:afjalshaik@example.com).

---

## Screenshots
Here’s what the application looks like:

![Screenshot 1](assets/screenshot1.png)
*Upload File Page*

![Screenshot 2](assets/screenshot2.png)
*Calculated Hash Value*

---

### Enjoy using HashGuard, and thanks for checking out the project! 😊
