class UserInterface:
    def __init__(self):
        self.setup_ui()

    def setup_ui(self):
        # Initialize the graphical user interface components
        print("Setting up the user interface...")

    def get_url_input(self):
        # Method to get URL input from the user
        url = input("Enter the URL to check: ")
        return url

    def display_results(self, results):
        # Method to display the results of the checks
        print("Results:")
        for result in results:
            print(result)