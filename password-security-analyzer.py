import customtkinter as ctk
import math
from PIL import Image  # For handling images with CTkImage

# Set the appearance mode and color theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class PasswordAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Security Analyzer")
        self.geometry("600x400")
        self.minsize(500, 350)

        self.after_id = None
        self.password_var = ctk.StringVar()
        self.password_hidden = True  # State for "Show Password"

        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Title label
        title_label = ctk.CTkLabel(self, text="Password Security Analyzer", font=("Arial", 20, "bold"))
        title_label.grid(row=0, column=0, pady=(20, 10), padx=20, sticky="n")

        # Top frame for password entry
        top_frame = ctk.CTkFrame(self, corner_radius=10)
        top_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        ctk.CTkLabel(top_frame, text="Enter Password:", font=("Arial", 14)).pack(side="left", padx=10)

        # Password Entry
        self.password_entry = ctk.CTkEntry(top_frame, textvariable=self.password_var, show="*", width=300, font=("Arial", 14))
        self.password_entry.pack(side="left", fill="x", expand=True, padx=10)
        self.password_entry.bind("<KeyRelease>", self.schedule_analysis)

        # Eye icon for "Show Password"
        self.eye_icon_open = ctk.CTkImage(light_image=Image.open("eye_open.png"), size=(24, 24))
        self.eye_icon_closed = ctk.CTkImage(light_image=Image.open("eye_closed.png"), size=(24, 24))
        self.show_password_button = ctk.CTkButton(
            top_frame,
            image=self.eye_icon_closed,
            text="",
            width=40,
            height=40,
            command=self.toggle_password_visibility
        )
        self.show_password_button.pack(side="left", padx=(10, 0))

        # Middle frame for strength bar
        middle_frame = ctk.CTkFrame(self, corner_radius=10)
        middle_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.strength_bar = ctk.CTkProgressBar(middle_frame, width=400, height=20)
        self.strength_bar.pack(pady=10)
        self.strength_bar.set(0)

        # Bottom frame for strength and time labels
        bottom_frame = ctk.CTkFrame(self, corner_radius=10)
        bottom_frame.grid(row=3, column=0, padx=20, pady=20, sticky="ew")

        self.strength_label = ctk.CTkLabel(bottom_frame, text="Strength: ", font=("Arial", 14))
        self.strength_label.pack(side="left", padx=10)

        self.time_label = ctk.CTkLabel(bottom_frame, text="Time to crack: ", font=("Arial", 14))
        self.time_label.pack(side="right", padx=10)  # Move to the right

    def toggle_password_visibility(self):
        """Toggle password visibility between hidden and visible."""
        self.password_hidden = not self.password_hidden
        if self.password_hidden:
            self.password_entry.configure(show="*")
            self.show_password_button.configure(image=self.eye_icon_closed)
        else:
            self.password_entry.configure(show="")
            self.show_password_button.configure(image=self.eye_icon_open)

    def schedule_analysis(self, event):
        """Debounce the analysis to avoid excessive computations."""
        if self.after_id:
            self.after_cancel(self.after_id)
        self.after_id = self.after(300, self.analyze_password)

    def analyze_password(self):
        """Analyze the password and update the GUI."""
        password = self.password_var.get()

        if not password:
            self.strength_bar.set(0)
            self.strength_label.configure(text="Strength: ")
            self.time_label.configure(text="Time to crack: ")
            return

        strength_score, strength_category = self.calculate_strength(password)
        time_to_crack = self.calculate_time_to_crack(strength_score)

        self.update_gui(strength_category, strength_score, time_to_crack)

    def calculate_strength(self, password):
        """Calculate password strength based on entropy."""
        char_sets = {
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'digits': any(c.isdigit() for c in password),
            'special': any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?/\\' for c in password)
        }

        N = 0
        if char_sets['uppercase']:
            N += 26
        if char_sets['lowercase']:
            N += 26
        if char_sets['digits']:
            N += 10
        if char_sets['special']:
            N += 32

        L = len(password)
        if N == 0 or L == 0:
            return 0, "Weak"

        H = L * math.log2(N)

        if H < 40:
            category = "Weak"
        elif 40 <= H < 80:
            category = "Moderate"
        else:
            category = "Strong"

        return H, category

    def calculate_time_to_crack(self, entropy):
        """Estimate time to crack the password in human-readable format."""
        guesses_per_second = 1e9  # 1 billion guesses per second
        time_seconds = 2 ** entropy / guesses_per_second

        if time_seconds < 1:
            if time_seconds < 1e-6:
                return "less than 1 microsecond"
            elif time_seconds < 1e-3:
                return f"{time_seconds * 1e6:.1f} microseconds"
            else:
                return f"{time_seconds * 1e3:.1f} milliseconds"

        units = [
            ("year", 31536000),
            ("day", 86400),
            ("hour", 3600),
            ("minute", 60),
            ("second", 1)
        ]

        # Convert seconds into larger units
        for unit, sec in units:
            if time_seconds >= sec:
                value = time_seconds / sec
                if value >= 1e12:
                    return f"{value / 1e12:.1f} trillion {unit}s"
                elif value >= 1e9:
                    return f"{value / 1e9:.1f} billion {unit}s"
                elif value >= 1e6:
                    return f"{value / 1e6:.1f} million {unit}s"
                elif value >= 1e3:
                    return f"{value / 1e3:.1f} thousand {unit}s"
                else:
                    return f"{value:.1f} {unit}s"

        return "over a trillion years"

    def update_gui(self, category, score, time_str):
        """Update the GUI with the analysis results."""
        if category == "Weak":
            bar_color = "red"
        elif category == "Moderate":
            bar_color = "yellow"
        else:
            bar_color = "green"

        # Update progress bar
        self.strength_bar.set(score / 100 if score <= 100 else 1)
        self.strength_bar.configure(progress_color=bar_color)

        # Update labels
        self.strength_label.configure(text=f"Strength: {category}")
        self.time_label.configure(text=f"Time to crack: {time_str}")


if __name__ == "__main__":
    app = PasswordAnalyzerApp()
    app.mainloop()
