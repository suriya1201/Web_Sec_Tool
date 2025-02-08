from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, END, messagebox

class UserInterface:
    def __init__(self):
        self.window = Tk()
        self.window.title("Web Security Tool")
        self.window.geometry("600x400")

        self.label = Label(self.window, text="Enter URL:")
        self.label.pack()

        self.url_entry = Entry(self.window, width=50)
        self.url_entry.pack()

        self.check_button = Button(self.window, text="Check", command=self.check_website)
        self.check_button.pack()

        self.result_text = Text(self.window, wrap='word', height=15)
        self.result_text.pack()

        self.scrollbar = Scrollbar(self.window, command=self.result_text.yview)
        self.scrollbar.pack(side='right', fill='y')
        self.result_text.config(yscrollcommand=self.scrollbar.set)

    def check_website(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return
        
        # Placeholder for actual checks
        result = f"Checking {url} for vulnerabilities...\n"
        result += "No vulnerabilities found."  # This should be replaced with actual check results

        self.result_text.delete(1.0, END)
        self.result_text.insert(END, result)

    def run(self):
        self.window.mainloop()