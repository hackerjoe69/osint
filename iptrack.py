import streamlit as st
import requests
import folium
from streamlit_folium import st_folium
import json
from datetime import datetime
import pytz
import speedtest
import os


# Configure page
st.set_page_config(
    page_title="IP Address Location Tracker",
    page_icon="🌍",
    layout="wide"
)

def validate_ip_address(ip):
    """Basic IP address validation"""
    if not ip:
        return True  # Empty is valid (will use public IP)
    
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except ValueError:
        return False

def get_public_ip():
    """Get public IP with multiple fallback services"""
    services = [
        "https://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "http://ip-api.com/json/"
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            if 'origin' in data:  # httpbin
                return data['origin']
            elif 'ip' in data:  # ipify
                return data['ip']
            elif 'query' in data:  # ip-api
                return data['query']
        except Exception:
            continue
    
    raise Exception("All IP detection services failed")

def check_vpn_status(ip_address, geo_data):
    """Check if IP appears to be using VPN/Proxy"""
    vpn_indicators = {
        'is_vpn': False,
        'confidence': 'Low',
        'indicators': [],
        'risk_score': 0,
        'debug_info': []
    }
    
    try:
        isp = geo_data.get('isp', '').lower()
        org = geo_data.get('org', '').lower()
        as_info = geo_data.get('as', '').lower()
        country = geo_data.get('country', '').lower()
        
        vpn_indicators['debug_info'].append(f"ISP: {isp}")
        vpn_indicators['debug_info'].append(f"Organization: {org}")
        vpn_indicators['debug_info'].append(f"AS: {as_info}")
        
        vpn_keywords = [
            'vpn', 'proxy', 'virtual private', 'private network', 'tunnel', 'anonymous',
            'privacy', 'secure', 'shield', 'guard', 'protect', 'hide', 'mask',
            'expressvpn', 'nordvpn', 'surfshark', 'cyberghost', 'purevpn', 
            'hotspot shield', 'windscribe', 'protonvpn', 'ipvanish', 'vyprvpn',
            'privatevpn', 'hidemyass', 'tunnelbear', 'zenmate', 'avast secureline',
            'kaspersky secure', 'mcafee safe', 'norton secure', 'bitdefender',
            'fastestssh', 'ssh tunnel', 'openvpn', 'wireguard', 'strongvpn'
        ]
        
        datacenter_keywords = [
            'hosting', 'datacenter', 'data center', 'cloud', 'server', 'vps',
            'dedicated', 'colocation', 'colo', 'infrastructure', 'services',
            'amazon', 'google', 'microsoft', 'digitalocean', 'linode', 'vultr',
            'ovh', 'hetzner', 'cloudflare', 'fastly', 'maxcdn', 'keycdn',
            'contabo', 'scaleway', 'rackspace', 'godaddy', 'hostgator',
            'bluehost', 'dreamhost', 'namecheap', 'hostinger'
        ]
        
        for keyword in vpn_keywords:
            if keyword in isp:
                vpn_indicators['indicators'].append(f'VPN keyword "{keyword}" found in ISP: {geo_data.get("isp", "")}')
                vpn_indicators['risk_score'] += 25
            if keyword in org:
                vpn_indicators['indicators'].append(f'VPN keyword "{keyword}" found in Organization: {geo_data.get("org", "")}')
                vpn_indicators['risk_score'] += 25
            if keyword in as_info:
                vpn_indicators['indicators'].append(f'VPN keyword "{keyword}" found in AS: {geo_data.get("as", "")}')
                vpn_indicators['risk_score'] += 20
        
        hosting_score = 0
        for keyword in datacenter_keywords:
            if keyword in isp:
                vpn_indicators['indicators'].append(f'Hosting keyword "{keyword}" in ISP: {geo_data.get("isp", "")}')
                hosting_score += 10
            if keyword in org:
                vpn_indicators['indicators'].append(f'Hosting keyword "{keyword}" in Organization: {geo_data.get("org", "")}')
                hosting_score += 10
            if keyword in as_info:
                vpn_indicators['indicators'].append(f'Hosting keyword "{keyword}" in AS: {geo_data.get("as", "")}')
                hosting_score += 8
        
        if hosting_score > 0:
            vpn_indicators['risk_score'] += min(hosting_score, 30)
        
        if geo_data.get('proxy', False):
            vpn_indicators['indicators'].append('Proxy flag detected by ip-api.com')
            vpn_indicators['risk_score'] += 40
        
        mobile_keywords = ['mobile', 'cellular', 'wireless', 'telecom', 'communications']
        is_mobile_isp = any(keyword in isp for keyword in mobile_keywords)
        is_datacenter = any(keyword in isp for keyword in datacenter_keywords)
        
        if is_datacenter and not is_mobile_isp:
            vpn_indicators['indicators'].append(f'Datacenter ISP detected: {geo_data.get("isp", "")}')
            vpn_indicators['risk_score'] += 20
        
        vpn_apis = [
            {
                'name': 'VPNAPI.io',
                'url': f"https://vpnapi.io/api/{ip_address}?key=free",
                'parser': lambda data: {
                    'vpn': data.get('security', {}).get('vpn', False) if isinstance(data.get('security'), dict) else False,
                    'proxy': data.get('security', {}).get('proxy', False) if isinstance(data.get('security'), dict) else False,
                    'tor': data.get('security', {}).get('tor', False) if isinstance(data.get('security'), dict) else False
                }
            }
        ]
        
        for api in vpn_apis:
            try:
                response = requests.get(api['url'], timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, dict):  # Ensure data is a dictionary
                        parsed = api['parser'](data)
                        
                        if parsed.get('vpn'):
                            vpn_indicators['indicators'].append(f'VPN detected by {api["name"]}')
                            vpn_indicators['risk_score'] += 35
                        
                        if parsed.get('proxy'):
                            vpn_indicators['indicators'].append(f'Proxy detected by {api["name"]}')
                            vpn_indicators['risk_score'] += 30
                        
                        if parsed.get('tor'):
                            vpn_indicators['indicators'].append(f'Tor network detected by {api["name"]}')
                            vpn_indicators['risk_score'] += 40
                            
            except Exception as e:
                vpn_indicators['debug_info'].append(f'{api["name"]} check failed: {str(e)}')
        
        try:
            ip_parts = ip_address.split('.')
            if len(ip_parts) == 4:
                last_octet = int(ip_parts[3])
                if last_octet in [1, 2, 3, 10, 50, 100]:
                    vpn_indicators['indicators'].append(f'Common VPN server IP pattern detected')
                    vpn_indicators['risk_score'] += 5
        except (ValueError, IndexError):
            vpn_indicators['debug_info'].append('Could not parse IP address for pattern analysis')
        
        vpn_friendly_countries = [
            'netherlands', 'switzerland', 'panama', 'romania', 'bulgaria',
            'moldova', 'seychelles', 'british virgin islands', 'cayman islands'
        ]
        
        if any(vpn_country in country for vpn_country in vpn_friendly_countries):
            if any(word in isp for word in ['hosting', 'server', 'cloud', 'datacenter']):
                vpn_indicators['indicators'].append(f'VPN-friendly country ({country}) with hosting ISP')
                vpn_indicators['risk_score'] += 15
        
        vpn_indicators['risk_score'] = min(vpn_indicators['risk_score'], 100)
        
        if vpn_indicators['risk_score'] >= 70:
            vpn_indicators['is_vpn'] = True
            vpn_indicators['confidence'] = 'Very High'
        elif vpn_indicators['risk_score'] >= 50:
            vpn_indicators['is_vpn'] = True
            vpn_indicators['confidence'] = 'High'
        elif vpn_indicators['risk_score'] >= 30:
            vpn_indicators['is_vpn'] = True
            vpn_indicators['confidence'] = 'Medium'
        elif vpn_indicators['risk_score'] >= 15:
            vpn_indicators['is_vpn'] = True
            vpn_indicators['confidence'] = 'Low'
        
        traditional_telecoms = [
            'comcast', 'verizon', 'at&t', 'charter', 'cox', 'spectrum',
            'british telecom', 'bt', 'virgin media', 'sky', 'orange',
            'vodafone', 'telefonica', 'deutsche telekom', 't-mobile',
            'sprint', 'rogers', 'bell canada', 'telus', 'shaw'
        ]
        
        is_traditional = any(telecom in isp for telecom in traditional_telecoms)
        if not is_traditional and isp and vpn_indicators['risk_score'] < 15:
            vpn_indicators['indicators'].append(f'Non-traditional ISP detected: {geo_data.get("isp", "")}')
            vpn_indicators['risk_score'] += 10
            if vpn_indicators['risk_score'] >= 15:
                vpn_indicators['is_vpn'] = True
                vpn_indicators['confidence'] = 'Low'
        
    except Exception as e:
        vpn_indicators['indicators'].append(f'Error during VPN check: {str(e)}')
        vpn_indicators['debug_info'].append(f'Exception: {str(e)}')
    
    return vpn_indicators

def measure_network_speed():
    """Measure network speed using speedtest-cli with proper configuration"""
    try:
        stest = speedtest.Speedtest(secure=True)
        
        # Configure user agent and other settings to avoid blocking
        stest.config['client']['useragent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Get servers and select best one
        stest.get_servers()
        stest.get_best_server()
        
        # Perform tests
        download = stest.download() / 1_000_000  # Convert to Mbps
        upload = stest.upload() / 1_000_000  # Convert to Mbps
        ping = stest.results.ping
        
        return {
            'download_speed': f"{download:.2f} Mbps",
            'upload_speed': f"{upload:.2f} Mbps",
            'ping': f"{ping:.2f} ms",
            'success': True,
            'error': None,
            'debug_info': [
                'Speed test completed successfully',
                f'Server: {stest.results.server["sponsor"]} ({stest.results.server["name"]})',
                f'Distance: {stest.results.server["d"]:.2f} km'
            ]
        }
    except speedtest.ConfigRetrievalError:
        return {
            'download_speed': 'N/A',
            'upload_speed': 'N/A', 
            'ping': 'N/A',
            'success': False,
            'error': "Speed test configuration failed - servers may be temporarily unavailable",
            'debug_info': ['Configuration retrieval failed', 'Try again in a few minutes']
        }
    except speedtest.NoMatchedServers:
        return {
            'download_speed': 'N/A',
            'upload_speed': 'N/A',
            'ping': 'N/A', 
            'success': False,
            'error': "No speed test servers available in your region",
            'debug_info': ['No matched servers found', 'Geographic location may not have nearby servers']
        }
    except speedtest.SpeedtestHTTPError as e:
        if "403" in str(e) or "Forbidden" in str(e):
            return {
                'download_speed': 'N/A',
                'upload_speed': 'N/A',
                'ping': 'N/A',
                'success': False,
                'error': "Speed test blocked by server (403 Forbidden) - try again later",
                'debug_info': [
                    'HTTP 403 Forbidden error',
                    'Server is blocking automated requests',
                    'This is temporary - try again in 5-10 minutes'
                ]
            }
        else:
            return {
                'download_speed': 'N/A',
                'upload_speed': 'N/A',
                'ping': 'N/A',
                'success': False,
                'error': f"Speed test HTTP error: {str(e)}",
                'debug_info': [f"HTTP error: {str(e)}"]
            }
    except Exception as e:
        error_msg = str(e).lower()
        if "403" in error_msg or "forbidden" in error_msg:
            return {
                'download_speed': 'N/A',
                'upload_speed': 'N/A',
                'ping': 'N/A',
                'success': False,
                'error': "Speed test temporarily blocked - please try again later",
                'debug_info': [
                    'Server returned 403 Forbidden',
                    'This usually resolves itself within 5-10 minutes',
                    'The blocking is temporary and automatic'
                ]
            }
        elif "timeout" in error_msg:
            return {
                'download_speed': 'N/A',
                'upload_speed': 'N/A',
                'ping': 'N/A',
                'success': False,
                'error': "Speed test timed out - check your internet connection",
                'debug_info': ['Connection timeout occurred', 'Network may be slow or unstable']
            }
        else:
            return {
                'download_speed': 'N/A',
                'upload_speed': 'N/A',
                'ping': 'N/A',
                'success': False,
                'error': f"Speed test failed: {str(e)}",
                'debug_info': [f"Speed test error: {str(e)}"]
            }

def get_weather_description(code):
    """Convert WMO weather codes to descriptions"""
    weather_codes = {
        0: "Clear sky",
        1: "Mainly clear",
        2: "Partly cloudy",
        3: "Overcast",
        45: "Fog",
        48: "Depositing rime fog",
        51: "Light drizzle",
        53: "Moderate drizzle",
        55: "Dense drizzle",
        56: "Light freezing drizzle",
        57: "Dense freezing drizzle",
        61: "Slight rain",
        63: "Moderate rain",
        65: "Heavy rain",
        66: "Light freezing rain",
        67: "Heavy freezing rain",
        71: "Slight snow fall",
        73: "Moderate snow fall",
        75: "Heavy snow fall",
        77: "Snow grains",
        80: "Slight rain showers",
        81: "Moderate rain showers",
        82: "Violent rain showers",
        85: "Slight snow showers",
        86: "Heavy snow showers",
        95: "Thunderstorm",
        96: "Thunderstorm with slight hail",
        99: "Thunderstorm with heavy hail"
    }
    return weather_codes.get(code, f"Unknown weather condition (code: {code})")

def display_results(results):
    """Display the tracking results"""
    if not results:
        return
    
    try:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📍 IP Information")
            st.write(f"**IP Address:** {results['ip_address']}")
            st.write(f"**ISP:** {results['isp']}")
            st.write(f"**Organization:** {results['org']}")
            st.write(f"**AS:** {results['as_info']}")
        
        with col2:
            st.subheader("🌐 Location Details")
            st.write(f"**City:** {results['city']}")
            st.write(f"**Region:** {results['region']}")
            st.write(f"**Country:** {results['country']}")
            st.write(f"**ZIP Code:** {results['zip_code']}")
            st.write(f"**Coordinates:** {results['lat']:.4f}, {results['lon']:.4f}")
        
        st.subheader("📡 Network Performance")
        if 'network' in results and results['network']:
            if results['network'].get('speed') and results['network']['speed'].get('success'):
                ncol1, ncol2 = st.columns(2)
                with ncol1:
                    st.metric("⬇️ Download Speed", results['network']['speed']['download_speed'])
                    st.metric("⬆️ Upload Speed", results['network']['speed']['upload_speed'])
                with ncol2:
                    st.metric("🏓 Ping", results['network']['speed']['ping'])
            else:
                error_msg = results['network']['speed'].get('error', 'Unknown error')
                st.warning(f"⚠️ Speed test failed: {error_msg}")
            
            with st.expander("🔍 Network Test Debug Info", expanded=False):
                if results['network']['speed'].get('debug_info'):
                    st.write("**Speed Test Debug:**")
                    for info in results['network']['speed']['debug_info']:
                        st.write(f"• {info}")
        else:
            st.warning("⚠️ Network performance data not available")
        
        if 'vpn_status' in results and results['vpn_status']:
            st.subheader("🔒 VPN/Proxy Analysis")
            vpn_info = results['vpn_status']
            
            if vpn_info['is_vpn']:
                if vpn_info['confidence'] in ['Very High', 'High']:
                    st.error(f"🚨 **VPN/Proxy Detected** (Confidence: {vpn_info['confidence']})")
                elif vpn_info['confidence'] == 'Medium':
                    st.warning(f"⚠️ **Likely VPN/Proxy** (Confidence: {vpn_info['confidence']})")
                else:
                    st.info(f"ℹ️ **Possible VPN/Proxy** (Confidence: {vpn_info['confidence']})")
            else:
                st.success("✅ **Direct Connection** - No VPN/Proxy detected")
            
            risk_color = "🔴" if vpn_info['risk_score'] >= 50 else "🟡" if vpn_info['risk_score'] >= 25 else "🟢"
            st.write(f"**Risk Score:** {risk_color} {vpn_info['risk_score']}/100")
            
            if vpn_info['indicators']:
                st.write("**Detection Indicators:**")
                for indicator in vpn_info['indicators']:
                    st.write(f"• {indicator}")
            
            if vpn_info.get('debug_info'):
                with st.expander("🔧 Debug Information", expanded=False):
                    for debug_item in vpn_info['debug_info']:
                        st.write(f"• {debug_item}")
            
            if vpn_info['is_vpn']:
                st.info("💡 **Note:** VPN/Proxy detection is based on various indicators and may not be 100% accurate.")
            else:
                st.info("💡 **Note:** If you're using a VPN and it's not detected, your VPN may be using residential IP addresses or advanced obfuscation techniques.")
        else:
            st.info("⚠️ VPN status check not available")
        
        st.subheader("🗺️ Location on Map")
        try:
            m = folium.Map(location=[results['lat'], results['lon']], zoom_start=12, tiles="OpenStreetMap")
            
            popup_text = f"""
            <b>{results['city']}, {results['country']}</b><br>
            IP: {results['ip_address']}<br>
            ISP: {results['isp']}<br>
            Coordinates: {results['lat']:.4f}, {results['lon']:.4f}
            """
            
            folium.Marker(
                [results['lat'], results['lon']],
                popup=folium.Popup(popup_text, max_width=300),
                tooltip="Click for details",
                icon=folium.Icon(color='red', icon='info-sign')
            ).add_to(m)
            
            folium.Circle(
                [results['lat'], results['lon']],
                radius=1000,
                color='blue',
                fill=True,
                fill_color='blue',
                fill_opacity=0.2,
                popup="Approximate location area"
            ).add_to(m)
            
            st_folium(m, width=700, height=500, key=f"map_{results['ip_address']}")
            
        except Exception as e:
            st.error(f"❌ Error creating map: {e}")
        
        st.subheader("🌤️ Current Weather")
        if 'weather' in results and results['weather']:
            wcol1, wcol2, wcol3 = st.columns(3)
            
            with wcol1:
                st.metric("🌡️ Temperature", results['weather']['temp'])
                st.metric("💧 Humidity", results['weather']['humidity'])
            
            with wcol2:
                st.metric("🤒 Feels Like", results['weather']['apparent_temp'])
                st.metric("🌧️ Precipitation", results['weather']['precipitation'])
            
            with wcol3:
                st.metric("💨 Wind Speed", results['weather']['wind_speed'])
                st.write(f"**🌤️ Conditions:** {results['weather']['description']}")
        else:
            st.warning("⚠️ Weather data not available")
        
        if 'webcams' in results and results['webcams']:
            st.subheader("📹 Nearby Webcams")
            st.success(f"Found {len(results['webcams'])} webcams within 50km")
            
            for i, cam in enumerate(results['webcams']):
                with st.expander(f"📷 {cam['title']}", key=f"webcam_{i}_{results['ip_address']}"):
                    if cam['image_url']:
                        st.image(cam['image_url'], caption=cam['title'], use_column_width=True)
                    
                    if cam['location']:
                        st.write(f"**Location:** {cam['location']}")
                    
                    if cam['embed_code']:
                        st.write("**Day Timelapse:**")
                        st.components.v1.html(cam['embed_code'], height=300)
        elif 'webcam_message' in results and results['webcam_message']:
            st.info(results['webcam_message'])
        
    except Exception as e:
        st.error(f"❌ Error displaying results: {str(e)}")

if 'tracking_results' not in st.session_state:
    st.session_state.tracking_results = None
if 'last_tracked_ip' not in st.session_state:
    st.session_state.last_tracked_ip = None
if 'show_results' not in st.session_state:
    st.session_state.show_results = False
if 'user_latitude' not in st.session_state:
    st.session_state.user_latitude = None
if 'user_longitude' not in st.session_state:
    st.session_state.user_longitude = None
if 'ip_input' not in st.session_state:
    st.session_state.ip_input = ""

# Title of the app
st.title("🌍 IP Address Location Tracker")

with st.sidebar:
    st.title("ℹ️ About")
    st.markdown("""
    This application allows you to track the geographical location of an IP address, check for VPN/proxy usage, measure network performance, and view nearby webcams.""")
    
    st.markdown("---")
    st.subheader("🚀 Quick Actions")
    
    # Get My Location button with actual geolocation
    if st.button("📍 Get My Location", key="get_location_btn"):
        st.info("📍 **Browser Geolocation Instructions:**")
        st.markdown("""
        1. Click 'Allow' when your browser asks for location permission
        2. Your coordinates will be displayed below
        3. Use these coordinates to manually enter a nearby IP for tracking
        """)
        
        st.components.v1.html("""
        <script>
        function getLocation() {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(showPosition, showError);
            } else {
                document.getElementById("location-result").innerHTML = "Geolocation is not supported by this browser.";
            }
        }
        
        function showPosition(position) {
            const lat = position.coords.latitude;
            const lon = position.coords.longitude;
            const accuracy = position.coords.accuracy;
            
            // Store coordinates in session storage for later use
            sessionStorage.setItem('user_latitude', lat);
            sessionStorage.setItem('user_longitude', lon);
            
            document.getElementById("location-result").innerHTML = 
                `<div style="background: #d4edda; padding: 10px; border-radius: 5px; margin: 10px 0;">
                    <strong>📍 Your Location:</strong><br>
                    Latitude: ${lat.toFixed(6)}<br>
                    Longitude: ${lon.toFixed(6)}<br>
                    Accuracy: ${accuracy.toFixed(0)} meters<br>
                    <small>✅ Coordinates saved for weather lookup</small>
                </div>`;
        }
        
        function showError(error) {
            let errorMsg = "";
            switch(error.code) {
                case error.PERMISSION_DENIED:
                    errorMsg = "User denied the request for Geolocation.";
                    break;
                case error.POSITION_UNAVAILABLE:
                    errorMsg = "Location information is unavailable.";
                    break;
                case error.TIMEOUT:
                    errorMsg = "The request to get user location timed out.";
                    break;
                case error.UNKNOWN_ERROR:
                    errorMsg = "An unknown error occurred.";
                    break;
            }
            document.getElementById("location-result").innerHTML = 
                `<div style="background: #f8d7da; padding: 10px; border-radius: 5px; margin: 10px 0;">
                    <strong>❌ Error:</strong> ${errorMsg}
                </div>`;
        }
        
        // Auto-run when loaded
        getLocation();
        </script>
        <div id="location-result">🔄 Getting your location...</div>
        """, height=150)
    
    if st.button("🌐 Get My IP", key="get_ip_btn"):
        try:
            with st.spinner("Getting your IP address..."):
                public_ip = get_public_ip()
                # Display IP directly in sidebar with persistent container
                st.session_state.current_public_ip = public_ip
                st.session_state.ip_input = public_ip
                st.rerun()
        except Exception as e:
            st.error(f"❌ Error getting IP: {e}")
    
    if 'current_public_ip' in st.session_state:
        st.info(f"🌐 **Your Current IP:** {st.session_state.current_public_ip}")
    
    # Get VPN Status button
    if st.button("🔒 Get VPN Status", key="get_vpn_btn"):
        try:
            with st.spinner("Checking VPN status..."):
                # Get current IP first
                current_ip = st.session_state.get('ip_input', '').strip()
                if not current_ip:
                    current_ip = get_public_ip()
                
                geo_url = f"http://ip-api.com/json/{current_ip}"
                geo_response = requests.get(geo_url, timeout=10)
                geo_response.raise_for_status()
                geo_data = geo_response.json()
                
                if geo_data.get('status') == 'success':
                    vpn_status = check_vpn_status(current_ip, geo_data)
                    
                    if vpn_status['is_vpn']:
                        if vpn_status['confidence'] in ['Very High', 'High']:
                            st.error(f"🚨 **VPN/Proxy Detected** (Confidence: {vpn_status['confidence']})")
                        elif vpn_status['confidence'] == 'Medium':
                            st.warning(f"⚠️ **Likely VPN/Proxy** (Confidence: {vpn_status['confidence']})")
                        else:
                            st.info(f"ℹ️ **Possible VPN/Proxy** (Confidence: {vpn_status['confidence']})")
                    else:
                        st.success("✅ **Direct Connection** - No VPN/Proxy detected")
                    
                    st.write(f"Risk Score: {vpn_status['risk_score']}/100")
                else:
                    st.error(f"❌ Could not check VPN status: {geo_data.get('message', 'Unknown error')}")
        except requests.exceptions.RequestException as e:
            st.error(f"❌ Network error checking VPN: {e}")
        except Exception as e:
            st.error(f"❌ Error checking VPN: {e}")
    
    if st.button("🌤️ Get Weather Report", key="get_weather_btn"):
        try:
            with st.spinner("Getting weather data..."):
                lat, lon = None, None
                location_source = ""
                
                try:
                    # Check if we have stored coordinates from geolocation
                    st.components.v1.html("""
                    <script>
                    const lat = sessionStorage.getItem('user_latitude');
                    const lon = sessionStorage.getItem('user_longitude');
                    if (lat && lon) {
                        // Send coordinates to parent window
                        window.parent.postMessage({
                            type: 'geolocation',
                            latitude: parseFloat(lat),
                            longitude: parseFloat(lon)
                        }, '*');
                    }
                    </script>
                    """, height=0)
                except:
                    pass
                
                if not lat or not lon:
                    current_ip = st.session_state.get('ip_input', '').strip()
                    if not current_ip:
                        try:
                            current_ip = get_public_ip()
                        except Exception as e:
                            st.error(f"❌ Could not get IP address: {e}")
                            st.stop()
                    
                    geo_url = f"http://ip-api.com/json/{current_ip}"
                    geo_response = requests.get(geo_url, timeout=10)
                    geo_response.raise_for_status()
                    geo_data = geo_response.json()
                    
                    if geo_data.get('status') == 'success':
                        lat = geo_data.get('lat')
                        lon = geo_data.get('lon')
                        city = geo_data.get('city', 'Unknown')
                        region = geo_data.get('regionName', 'Unknown')
                        country = geo_data.get('country', 'Unknown')
                        location_source = f"📍 Using IP-based location: {city}, {region}, {country}"
                    else:
                        st.error(f"❌ Could not determine location: {geo_data.get('message', 'Unknown error')}")
                        st.stop()
                else:
                    location_source = "📍 Using your precise GPS location"
                
                if lat and lon:
                    st.info(location_source)
                    
                    weather_url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m&timezone=auto"
                    weather_response = requests.get(weather_url, timeout=10)
                    weather_response.raise_for_status()
                    weather_data = weather_response.json()
                    
                    if 'current' in weather_data:
                        current = weather_data['current']
                        temp = current.get('temperature_2m', 'N/A')
                        humidity = current.get('relative_humidity_2m', 'N/A')
                        apparent_temp = current.get('apparent_temperature', 'N/A')
                        wind_speed = current.get('wind_speed_10m', 'N/A')
                        weather_code = current.get('weather_code', 0)
                        
                        weather_desc = get_weather_description(weather_code)
                        
                        st.success("🌤️ **Current Weather:**")
                        st.write(f"🌡️ **Temperature:** {temp}°C")
                        st.write(f"🤒 **Feels Like:** {apparent_temp}°C")
                        st.write(f"💧 **Humidity:** {humidity}%")
                        st.write(f"💨 **Wind Speed:** {wind_speed} km/h")
                        st.write(f"☁️ **Conditions:** {weather_desc}")
                    else:
                        st.error("❌ Weather data not available")
                else:
                    st.error("❌ Could not determine location for weather")
        except requests.exceptions.RequestException as e:
            st.error(f"❌ Network error getting weather: {e}")
        except Exception as e:
            st.error(f"❌ Error getting weather: {e}")

# Input fields
ip_address = st.text_input("Enter IP Address (leave blank for your public IP):", key="ip_input")

windy_api_key = st.text_input("Windy API Key (for webcams, optional):", type="password", key="windy_key", 
                             help="Get a free API key at https://api.windy.com/keys")

# Buttons
button_col1, button_col2 = st.columns([1, 1])

with button_col1:
    track_button = st.button("🔍 Track Location", key="track_btn")

with button_col2:
    if st.session_state.show_results and st.session_state.tracking_results:
        clear_button = st.button("🗑️ Clear Results", key="clear_btn")
        if clear_button:
            st.session_state.tracking_results = None
            st.session_state.last_tracked_ip = None
            st.session_state.show_results = False
            st.rerun()

# Track location logic
if track_button:
    if ip_address and not validate_ip_address(ip_address):
        st.error("❌ Invalid IP address format. Please enter a valid IPv4 address.")
    else:
        current_ip = ip_address.strip()
        
        if not current_ip:
            try:
                with st.spinner("Getting your public IP address..."):
                    current_ip = get_public_ip()
                    st.info(f"ℹ️ Using your public IP: {current_ip}")
            except Exception as e:
                st.error(f"❌ Error fetching public IP: {e}")
                st.stop()

        need_new_data = (
            not st.session_state.tracking_results or 
            st.session_state.last_tracked_ip != current_ip
        )
        
        if need_new_data:
            try:
                with st.spinner("Fetching location data..."):
                    geo_url = f"http://ip-api.com/json/{current_ip}"
                    geo_response = requests.get(geo_url, timeout=10)
                    geo_response.raise_for_status()
                    geo_data = geo_response.json()
                    
                    if geo_data.get('status') == 'fail':
                        st.error(f"❌ Error: {geo_data.get('message', 'Unknown error')}")
                        st.stop()
                    
                    lat = geo_data.get('lat')
                    lon = geo_data.get('lon')
                    
                    if lat is None or lon is None:
                        st.error("❌ Unable to determine coordinates for this IP address.")
                        st.stop()
                    
                    city = geo_data.get('city', 'Unknown')
                    region = geo_data.get('regionName', 'Unknown')
                    country = geo_data.get('country', 'Unknown')
                    zip_code = geo_data.get('zip', 'N/A')
                    isp = geo_data.get('isp', 'Unknown')
                    org = geo_data.get('org', 'N/A')
                    as_info = geo_data.get('as', 'N/A')
                    
                    results = {
                        'ip_address': current_ip,
                        'lat': lat,
                        'lon': lon,
                        'city': city,
                        'region': region,
                        'country': country,
                        'zip_code': zip_code,
                        'isp': isp,
                        'org': org,
                        'as_info': as_info,
                        'weather': None,
                        'webcams': [],
                        'webcam_message': None,
                        'vpn_status': None,
                        'network': None
                    }
                    
                    try:
                        with st.spinner("Checking VPN/Proxy status..."):
                            vpn_status = check_vpn_status(current_ip, geo_data)
                            results['vpn_status'] = vpn_status
                    except Exception as e:
                        st.warning(f"⚠️ Could not check VPN status: {e}")
                        results['vpn_status'] = {
                            'is_vpn': False,
                            'confidence': 'Unknown',
                            'indicators': [f'VPN check failed: {str(e)}'],
                            'risk_score': 0
                        }
                    
                    try:
                        with st.spinner("Measuring network performance..."):
                            speed_result = measure_network_speed()
                            results['network'] = {
                                'speed': speed_result
                            }
                    except Exception as e:
                        st.warning(f"⚠️ Could not measure network performance: {e}")
                        results['network'] = {
                            'speed': {
                                'download_speed': 'N/A',
                                'upload_speed': 'N/A',
                                'ping': 'N/A',
                                'success': False,
                                'error': str(e),
                                'debug_info': [f"Network performance error: {str(e)}"]
                            }
                        }
                    
                    try:
                        with st.spinner("Fetching weather data..."):
                            weather_url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m,wind_direction_10m&timezone=auto"
                            weather_response = requests.get(weather_url, timeout=10)
                            weather_response.raise_for_status()
                            weather_data = weather_response.json()
                            
                            if 'current' in weather_data and isinstance(weather_data['current'], dict):
                                current = weather_data['current']
                                temp = current.get('temperature_2m', 'N/A')
                                humidity = current.get('relative_humidity_2m', 'N/A')
                                apparent_temp = current.get('apparent_temperature', 'N/A')
                                precipitation = current.get('precipitation', 0)
                                wind_speed = current.get('wind_speed_10m', 'N/A')
                                weather_code = current.get('weather_code', 0)
                                
                                weather_desc = get_weather_description(weather_code)
                                
                                results['weather'] = {
                                    'temp': f"{temp}°C" if temp != 'N/A' else 'N/A',
                                    'humidity': f"{humidity}%" if humidity != 'N/A' else 'N/A',
                                    'apparent_temp': f"{apparent_temp}°C" if apparent_temp != 'N/A' else 'N/A',
                                    'precipitation': f"{precipitation} mm",
                                    'wind_speed': f"{wind_speed} km/h" if wind_speed != 'N/A' else 'N/A',
                                    'description': weather_desc
                                }
                            else:
                                st.warning("⚠️ Weather data format unexpected")
                                
                    except requests.exceptions.RequestException as e:
                        st.warning(f"⚠️ Could not fetch weather data: Network error - {e}")
                    except Exception as e:
                        st.warning(f"⚠️ Could not fetch weather data: {e}")
                    
                    if windy_api_key.strip():
                        try:
                            with st.spinner("Searching for nearby webcams..."):
                                webcam_url = f"https://api.windy.com/api/webcams/v3/list/nearby={lat},{lon},50"
                                headers = {'x-windy-key': windy_api_key.strip()}
                                params = {'show': 'webcams:location,image,player'}
                                
                                webcam_response = requests.get(webcam_url, headers=headers, params=params, timeout=15)
                                webcam_response.raise_for_status()
                                webcam_data = webcam_response.json()
                                
                                if isinstance(webcam_data, dict) and webcam_data.get('status') == 'OK' and 'result' in webcam_data:
                                    webcams = webcam_data['result'].get('webcams', [])
                                    if webcams and isinstance(webcams, list):
                                        for i, cam in enumerate(webcams[:5]):
                                            if isinstance(cam, dict):
                                                cam_data = {
                                                    'title': cam.get('title', f'Webcam {i+1}'),
                                                    'image_url': None,
                                                    'location': None,
                                                    'embed_code': None
                                                }
                                                
                                                if 'image' in cam and isinstance(cam['image'], dict) and 'current' in cam['image'] and isinstance(cam['image']['current'], dict) and 'preview' in cam['image']['current']:
                                                    cam_data['image_url'] = cam['image']['current']['preview']
                                                
                                                if 'location' in cam and isinstance(cam['location'], dict):
                                                    loc = cam['location']
                                                    cam_data['location'] = f"{loc.get('city', 'Unknown')}, {loc.get('region', 'Unknown')}"
                                                
                                                if 'player' in cam and isinstance(cam['player'], dict) and 'day' in cam['player'] and isinstance(cam['player']['day'], dict) and 'embed' in cam['player']['day']:
                                                    cam_data['embed_code'] = cam['player']['day']['embed']
                                                
                                                results['webcams'].append(cam_data)
                                    else:
                                        results['webcam_message'] = "ℹ️ No webcams found within 50km of this location."
                                else:
                                    error_msg = webcam_data.get('message', 'Unknown error') if isinstance(webcam_data, dict) else 'Invalid response format'
                                    results['webcam_message'] = f"⚠️ Webcam API response: {error_msg}"
                                    
                        except requests.exceptions.RequestException as e:
                            results['webcam_message'] = f"❌ Network error fetching webcams: {e}"
                        except Exception as e:
                            results['webcam_message'] = f"❌ Error fetching webcams: {e}"
                    else:
                        results['webcam_message'] = "💡 **Tip:** Provide a Windy API Key to view nearby webcams. Get one free at https://api.windy.com/keys"
                    
                    st.session_state.tracking_results = results
                    st.session_state.last_tracked_ip = current_ip
                    st.session_state.show_results = True
                    
                    st.success("✅ Location data fetched successfully!")
            
            except requests.exceptions.Timeout:
                st.error("❌ Request timed out. Please check your internet connection and try again.")
            except requests.exceptions.RequestException as e:
                st.error(f"❌ Network error: {e}")
            except json.JSONDecodeError:
                st.error("❌ Invalid response format from geolocation service.")
            except Exception as e:
                st.error(f"❌ Unexpected error: {e}")
        else:
            st.session_state.show_results = True
            st.info("ℹ️ Showing cached results for this IP address.")

# Display results if available
if st.session_state.show_results and st.session_state.tracking_results:
    st.markdown("---")
    st.subheader(f"📊 Results for IP: {st.session_state.tracking_results['ip_address']}")
    display_results(st.session_state.tracking_results)

# Add footer with dynamic date and time
st.markdown("---")
try:
    wat_tz = pytz.timezone('Africa/Lagos')
    current_time = datetime.now(wat_tz)
    formatted_time = current_time.strftime("%I:%M %p WAT on %A, %B %d, %Y")
    st.markdown(f"**Current Time:** {formatted_time}")
except Exception as e:
    # Fallback to UTC if timezone fails
    current_time = datetime.utcnow()
    formatted_time = current_time.strftime("%I:%M %p UTC on %A, %B %d, %Y")
    st.markdown(f"**Current Time:** {formatted_time}")

st.markdown("**Note:** This tool shows approximate location based on IP geolocation. Accuracy may vary.")
st.markdown("**Privacy:** No IP addresses or location data are stored by this application.")
st.markdown("**Network Tests:** Speed tests are approximate and depend on server availability.")
st.markdown("Developed by Hacker Joe.")