# College Examination Portal

Flask implementation of the admin and student examination portal.

## Run locally

1. Install Python 3.10+.
2. Run `pip install -r requirements.txt`.
3. Run `python app.py` and open `http://127.0.0.1:5000`.

Create an admin account first, then set up classrooms, add students, create an exam allocation, and add marks. Data is stored locally in `exam_portal.db`.

The Forgot Password workflow is implemented as a local reset-link simulation: after the registered email is verified, it continues directly to the reset page. Connect an email provider before deploying it to send real email.

## Email OTP login

Admin and student logins require a six-digit OTP sent to the email registered on the account. Configure `MAIL_SERVER`, `MAIL_PORT` (usually `587`), `MAIL_USERNAME`, `MAIL_PASSWORD`, and `MAIL_FROM` before starting the app. For Gmail, use `smtp.gmail.com` and a Google App Password rather than your regular Gmail password.
