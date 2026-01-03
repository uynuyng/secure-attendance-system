# Secure Attendance Management System

A web-based attendance application built with **Flask** and **Oracle Database**, featuring advanced security implementations including **Hybrid Encryption (RSA + AES)**, **Virtual Private Database (VPD)**, and **Fine-Grained Auditing (FGA)**.

## Key Features

### Security & Cryptography
* **Hybrid Encryption:** Implements RSA (Asymmetric) and AES (Symmetric) to encrypt sensitive attendance data (Device Info, Location) directly within the database using PL/SQL Packages.
* **Secure Authentication:** Password hashing with Salt and SHA-256.
* **Dynamic OTP & QR Code:** Time-based OTP and QR Code generation for secure check-ins, preventing replay attacks.
* **Database Security:**
    * **VPD (Virtual Private Database):** Row-level security ensuring students can only view their own records.
    * **FGA (Fine-Grained Auditing):** Tracks sensitive data access (SELECT/UPDATE) on critical tables.
    * **Standard Auditing:** Logs all user login attempts and critical system actions.

### Functional Modules
* **Administrator:** User management, class assignment, view security reports & audit logs.
* **Teacher:** Schedule management, generate attendance QR codes, export reports to Excel.
* **Student:** Scan QR/Enter OTP for attendance, view personal history.

## Tech Stack

* **Backend:** Python (Flask Framework)
* **Database:** Oracle Database 19c (PL/SQL, Triggers, Stored Procedures)
* **Frontend:** HTML5, CSS3, JavaScript
* **Libraries:** `oracledb`, `flask-sqlalchemy`, `cryptography`, `qrcode`, `pandas`

## Disclaimer

This project is for educational purposes as part of the **Information Security** course at **Ho Chi Minh City University of Industry and Trade (HUIT)**.
