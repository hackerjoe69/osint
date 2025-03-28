import geocoder
import webbrowser

# Prompt the user to enter the IP address of the device to be tracked
ip_address = input("Enter the IP address of the device to be tracked: ")

# Retrieve the location data for the specified IP address
location = geocoder.ip(ip_address)

# Extract the latitude and longitude from the location data
latitude = location.latlng[0]
longitude = location.latlng[1]

# Generate a Google Maps URL with the latitude and longitude
map_url = f"https://www.google.com/maps/search/?api=1&query={latitude},{longitude}"

# Open the Google Maps URL in the default web browser
webbrowser.open(map_url)

# Print the current location
print(f"Latitude: {latitude}, Longitude: {longitude}")