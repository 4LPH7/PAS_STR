# Password Security Analyzer

## Overview
Password Security Analyzer is an interactive GUI application designed to evaluate the strength of your passwords and estimate the time required to crack them. It uses modern computational methods and a user-friendly interface to make password security assessment accessible to everyone.

---

## Features

- **Password Strength Analysis**:
  - Calculates entropy-based password strength.
  - Categorizes passwords as Weak, Moderate, or Strong.

- **Dynamic UI**:
  - Real-time updates as you type your password.
  - Progress bar changes color based on password strength (red, yellow, green).

- **Password Visibility Toggle**:
  - Toggle between showing and hiding the password using an eye icon.

- **Responsive Design**:
  - Automatically adjusts to different screen sizes.

---

## Requirements

- Python 3.7 or higher
- Required Python libraries:
  - `customtkinter`
  - `Pillow`

---

## Installation

1. Clone the repository or download the source code:
   ```bash
   git clone https://github.com/4LPH7/PAS_STR.git
   cd PAS_STR
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Place the `eye_open.png` and `eye_closed.png` icons in the same directory as the script.

4. Run the application:
   ```bash
   python app.py
   ```

---

## Usage

1. Open the application.
2. Enter a password in the input field.
3. View the strength and estimated time to crack in the provided output labels.
4. Use the eye icon to toggle password visibility.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

