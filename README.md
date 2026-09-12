# Phishing Website Detection System

A beginner-friendly Django college project that checks URLs for common phishing indicators.

## Features
- User registration and login
- URL checking
- Rule-based phishing score
- Safe / Suspicious / Phishing classification
- Detection history
- Admin panel

## Run
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```
Open http://127.0.0.1:8000/

This version uses explainable rule-based detection, suitable for a college demonstration. It does not visit or execute the submitted website.


## Deploy on Render
This project is prepared for Render. Push the project to GitHub, then create a Render Blueprint from the repository. The included `render.yaml` creates the web service and PostgreSQL database automatically.

Important: Render Free web services sleep after 15 minutes of inactivity, and Free PostgreSQL databases expire after 30 days. For a college/demo deployment this is usually fine; for long-term data storage, use a paid database plan.
