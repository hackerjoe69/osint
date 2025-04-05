import webbrowser

# Ask the user for the IP address of the webcam
ip_address = input("Enter the IP address of the webcam: ")

# Construct the URL for the webcam view
url = f"http://{ip_address}/"

# Open the webcam view in the default browser
webbrowser.open(url)