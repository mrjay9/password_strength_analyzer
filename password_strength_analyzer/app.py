import tkinter as tk
from tkinter import ttk
import re
import math
import string
import json
import os

class PasswordStrengthAnalyzer:
    def __init__(self):
        # Load common passwords list
        self.common_passwords = self._load_common_passwords()
        # Load common patterns
        self.common_patterns = [
            r'12345', r'qwerty', r'asdfg', r'zxcvb', r'password',
            r'abcde', r'\d{4}', r'[a-z]{5,}', r'[A-Z]{5,}'
        ]

    def _load_common_passwords(self):
        """Load a small set of common passwords."""
        common_list = [
            "123456", "password", "123456789", "12345678", "12345", "qwerty",
            "123123", "111111", "abc123", "1234567", "admin", "welcome",
            "monkey", "login", "letmein", "dragon", "master", "sunshine", 
            "ashley", "bailey", "passw0rd", "shadow", "superman", "qazwsx",
            "michael", "football", "baseball", "iloveyou", "trustno1", "jennifer"
        ]
        return set(common_list)

    def analyze_password(self, password):
        """Analyze password strength and return score and feedback."""
        if not password:
            return {
                "score": 0,
                "label": "Very Weak",
                "feedback": ["Password cannot be empty"],
                "color": "#FF0000"  # Red
            }

        # Initialize score and feedback
        score = 0
        feedback = []
        
        # Check length - Improved scoring for length
        length = len(password)
        length_score = min(length * 1.0, 25)  # Max 25 points for length (up from 10)
        score += length_score
        
        if length < 8:
            feedback.append("Password is too short (at least 8 characters recommended)")
        
        # Check character variety - Improved scoring
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9\s]', password))
        
        # Increased points for character variety
        variety_score = (has_lowercase + has_uppercase + has_digit + has_special) * 10  # Up from 5
        score += variety_score
        
        variety_feedback = []
        if not has_lowercase:
            variety_feedback.append("Add lowercase letters")
        if not has_uppercase:
            variety_feedback.append("Add uppercase letters")
        if not has_digit:
            variety_feedback.append("Add numeric digits")
        if not has_special:
            variety_feedback.append("Add special characters (!@#$%^&*)")
        
        # Only add variety feedback if not all criteria are met
        if variety_feedback:
            feedback.extend(variety_feedback)
        
        # Calculate and score distribution of characters
        char_distribution_score = self._calculate_distribution_score(password)
        score += char_distribution_score
        
        # Check for entropy/randomness - Improved calculation
        entropy = self._calculate_entropy(password)
        entropy_score = min(entropy / 3, 20)  # Max 20 points for entropy (up from 15)
        score += entropy_score
        
        if entropy < 40 and length >= 8:
            feedback.append("Increase password complexity and randomness")
        
        # Check for common passwords - more severe penalty
        if password.lower() in self.common_passwords:
            score = max(0, score - 30)  # More severe penalty (up from 20)
            feedback.append("This is a commonly used password")
        
        # Check for common patterns - adjusted penalty
        pattern_found = False
        for pattern in self.common_patterns:
            if re.search(pattern, password):
                pattern_found = True
                break
                
        if pattern_found:
            score = max(0, score - 15)  # Adjusted penalty (up from 10)
            feedback.append("Avoid common patterns (like '12345', 'qwerty')")
            
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):  # 3 or more repeated chars
            score = max(0, score - 10)  # Increased penalty (up from 5)
            feedback.append("Avoid repeating characters")
            
        # Add bonus for meeting all basic recommendations
        if length >= 12 and has_lowercase and has_uppercase and has_digit and has_special and not pattern_found:
            score += 15  # Bonus points for following all recommendations
        
        # Normalize score (0-100)
        score = max(0, min(100, score))
        
        # Determine strength label and color
        label, color = self._get_strength_label(score)
        
        # If no specific feedback, give general advice
        if not feedback and score < 80:
            feedback.append("Consider a longer password with more variety")
        elif not feedback:
            feedback.append("Great password!")
            
        return {
            "score": score,
            "label": label,
            "feedback": feedback,
            "color": color
        }
    
    def _calculate_distribution_score(self, password):
        """Calculate score based on character distribution."""
        if len(password) < 2:
            return 0
            
        # Count occurrences of each character
        char_count = {}
        for char in password:
            char_count[char] = char_count.get(char, 0) + 1
            
        # Calculate distribution score based on how evenly distributed characters are
        avg = len(password) / len(char_count) if char_count else 0
        variance = sum((count - avg) ** 2 for count in char_count.values()) / len(char_count) if char_count else 0
        
        # Lower variance means better distribution
        distribution_score = max(0, 10 - min(variance, 10))
        return distribution_score
    
    def _calculate_entropy(self, password):
        """Calculate password entropy (bits of randomness)."""
        # Count character sets used
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'\d', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9\s]', password): charset_size += 33
        
        if charset_size == 0:  # Edge case
            return 0
            
        # Calculate entropy using Shannon's formula
        entropy = math.log2(charset_size) * len(password)
        return entropy
    
    def _get_strength_label(self, score):
        """Convert numerical score to descriptive label and color."""
        if score < 20:
            return "Very Weak", "#FF0000"  # Red
        elif score < 40:
            return "Weak", "#FF9900"  # Orange
        elif score < 60:
            return "Moderate", "#FFCC00"  # Yellow
        elif score < 80:
            return "Strong", "#99CC00"  # Light green
        else:
            return "Very Strong", "#00CC00"  # Green

class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("550x450")
        self.root.resizable(False, False)
        
        # Add some padding around the window
        self.mainframe = ttk.Frame(root, padding="20")
        self.mainframe.pack(fill=tk.BOTH, expand=True)
        
        # Create analyzer instance
        self.analyzer = PasswordStrengthAnalyzer()
        
        # Create and place widgets
        self._create_widgets()
        
    def _create_widgets(self):
        # Title label
        title_label = ttk.Label(
            self.mainframe, 
            text="Password Strength Analyzer", 
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # Password input frame
        input_frame = ttk.Frame(self.mainframe)
        input_frame.pack(fill=tk.X, pady=10)
        
        password_label = ttk.Label(
            input_frame, 
            text="Enter Password:", 
            font=("Arial", 12)
        )
        password_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Password entry with show="*" to hide characters
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            input_frame, 
            textvariable=self.password_var, 
            font=("Arial", 12),
            show="•",  # Use bullet for masking password
            width=30
        )
        self.password_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.password_entry.bind("<KeyRelease>", self._on_password_change)
        
        # Toggle button to show/hide password
        self.show_password = tk.BooleanVar(value=False)
        self.toggle_btn = ttk.Checkbutton(
            input_frame, 
            text="Show", 
            variable=self.show_password,
            command=self._toggle_password_visibility
        )
        self.toggle_btn.pack(side=tk.LEFT)
        
        # Generate Password button
        self.generate_btn = ttk.Button(
            self.mainframe,
            text="Generate Strong Password",
            command=self._generate_password
        )
        self.generate_btn.pack(pady=(0, 10))
        
        # Results frame
        results_frame = ttk.LabelFrame(
            self.mainframe, 
            text="Analysis Results",
            padding=10
        )
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Strength meter (progress bar)
        meter_frame = ttk.Frame(results_frame)
        meter_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(
            meter_frame, 
            text="Strength:", 
            font=("Arial", 11)
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.strength_var = tk.StringVar(value="Very Weak")
        self.strength_label = ttk.Label(
            meter_frame, 
            textvariable=self.strength_var,
            font=("Arial", 11, "bold")
        )
        self.strength_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Score display
        self.score_var = tk.StringVar(value="0/100")
        ttk.Label(
            meter_frame,
            textvariable=self.score_var,
            font=("Arial", 11)
        ).pack(side=tk.RIGHT)
        
        # Create a custom styled progressbar
        self.style = ttk.Style()
        self.style.configure("red.Horizontal.TProgressbar", background='red')
        
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            results_frame,
            orient=tk.HORIZONTAL,
            length=500,
            mode='determinate',
            variable=self.progress_var,
            style="red.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        # Feedback frame
        feedback_frame = ttk.LabelFrame(
            results_frame, 
            text="Recommendations",
            padding=10
        )
        feedback_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Scrollable text widget for feedback
        self.feedback_text = tk.Text(
            feedback_frame,
            height=8,
            width=50,
            wrap=tk.WORD,
            font=("Arial", 11),
            background="#F0F0F0",
            relief=tk.FLAT
        )
        self.feedback_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(
            feedback_frame, 
            orient=tk.VERTICAL, 
            command=self.feedback_text.yview
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.feedback_text.config(yscrollcommand=scrollbar.set)
        self.feedback_text.config(state=tk.DISABLED)  # Make read-only
        
        # Initial analysis (empty)
        self._update_analysis("")
    
    def _toggle_password_visibility(self):
        """Toggle between showing and hiding the password."""
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def _on_password_change(self, event=None):
        """Handle password entry changes."""
        password = self.password_var.get()
        self._update_analysis(password)
    
    def _update_analysis(self, password):
        """Update UI with password analysis results."""
        # Get analysis from the analyzer
        result = self.analyzer.analyze_password(password)
        score = result["score"]
        label = result["label"]
        feedback = result["feedback"]
        color = result["color"]
        
        # Update progress bar
        self.progress_var.set(score)
        self.style.configure("red.Horizontal.TProgressbar", background=color)
        
        # Update strength label
        self.strength_var.set(label)
        
        # Update score display
        self.score_var.set(f"{int(score)}/100")
        
        # Update feedback text
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        
        if feedback:
            for i, item in enumerate(feedback, 1):
                self.feedback_text.insert(tk.END, f"{i}. {item}\n")
        else:
            self.feedback_text.insert(tk.END, "No specific recommendations.")
            
        self.feedback_text.config(state=tk.DISABLED)
    
    def _generate_password(self):
        """Generate a strong random password."""
        import random
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        # Generate password with good mix of characters
        length = random.randint(12, 16)
        
        # Ensure at least one character from each set
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + special
        password.extend(random.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password
        random.shuffle(password)
        
        # Set the password in the entry
        password_str = ''.join(password)
        self.password_var.set(password_str)
        self._update_analysis(password_str)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()