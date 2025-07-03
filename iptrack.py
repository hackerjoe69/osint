import geocoder
import webbrowser

# Prompt the user to enter the phone number with the country code
phone_number = input("Enter the phone number with country code (e.g., +1234567890): ")

# Validate the phone number format
print("Attempting to retrieve location for the phone number...")

location = geocoder.ip('me')  # Replace this line with your actual geolocation logic

# Extract the latitude and longitude from the location data
latitude = location.latlng[0]
longitude = location.latlng[1]

# Generate a Google Maps URL with the latitude and longitude
map_url = f"https://www.google.com/maps/search/?api=1&query={latitude},{longitude}"

# Open the Google Maps URL in the default web browser
webbrowser.open(map_url)

# Print the current location
print(f"Latitude: {latitude}, Longitude: {longitude}")