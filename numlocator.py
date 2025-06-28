import phonenumbers
from myphone import number
import folium
import webbrowser  # ✅ Added to open Google Maps

from phonenumbers import geocoder
from phonenumbers import carrier
from opencage.geocoder import OpenCageGeocode

# Parse number and get location
pepnumber = phonenumbers.parse(number)
location = geocoder.description_for_number(pepnumber, "en")
print("Location:", location)

# Get service provider
service_provider = phonenumbers.parse(number)
print("Carrier:", carrier.name_for_number(service_provider, "en"))

# OpenCage API setup
key = "your key here"  # Replace with your actual API key
geocoder = OpenCageGeocode(key)
query = str(location)
results = geocoder.geocode(query)

if results:
    lat = results[0]['geometry']['lat']
    lng = results[0]['geometry']['lng']
    print("Latitude:", lat)
    print("Longitude:", lng)

    # Create and save map
    myMap = folium.Map(location=[lat, lng], zoom_start=9)
    folium.Marker([lat, lng], popup=location).add_to(myMap)
    myMap.save("mylocation.html")

    # ✅ Open Google Maps with exact location
    google_maps_url = f"https://www.google.com/maps?q={lat},{lng}"
    webbrowser.open(google_maps_url)

else:
    print("Location could not be determined.")
