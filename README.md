# Integrity Checker

Integrity Checker is a web application that allows users to upload files and calculate their integrity using MD5 hash algorithm. It can be used to verify the integrity and authenticity of files.
And also it is used to scan malicious websites using Virus Total API's and also used to scan a directory on yoyr pc.


## Features

- Upload files for integrity checking.
- Calculate hash values using MD5 algorithms.
- Built with Django and Python.
- Scan malicious urls.
- scan a file and directory.  

## Getting Started

To run this project locally, follow these steps:


Certainly, here's a sample README file that you can use for your Integrity Checker project. You can customize it further to provide more details about your project.

markdown
Copy code
# Integrity Checker

Integrity Checker is a web application that allows users to upload files and calculate their integrity using various hash algorithms. It can be used to verify the integrity and authenticity of files.

## Features

- Upload files for integrity checking.
- Calculate hash values using different algorithms (e.g., MD5, SHA-256, SHA-512).
- Display the calculated hash values and timestamps.
- Built with Django and Python.

## Getting Started

To run this project locally, follow these steps:

1. Clone this repository:

git clone https://github.com/somesh-jyothula/integrity-checker.git

Navigate to the project directory:


cd integrity-checker

Create a virtual environment (optional but recommended):

python -m venv venv

Activate the virtual environment:

On Windows:

venv\Scripts\activate

On macOS and Linux:

source venv/bin/activate


Apply database migrations:

python manage.py migrate


Start the development server:


python manage.py runserver


Visit http://127.0.0.1:8000/ in your web browser to access the Integrity Checker.

