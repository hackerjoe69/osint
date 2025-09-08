import os
import json
from datetime import datetime

import requests
import streamlit as st
import folium
from streamlit_folium import st_folium
import socket
import pytz

# speedtest-cli package exposes module "speedtest"
try:
    import speedtest  # pip install speedtest-cli
except Exception:
    speedtest = None


# ----------------------------
# Page config
# ----------------------------
st.set_page_config(
    page_title="IP Address Location Tracker",
    page_icon="🌍",
    layout="wide",
)

# ----------------------------
# Utilities
# ----------------------------
def safe_get_json(url: str, timeout: int = 10, headers: dict | None = None, params: dict | None = None):
    """Requests JSON with solid error handling."""
    resp = requests.get(url, timeout=timeout, headers=headers, params=params)
    resp.raise_for_status()
    try:
        return resp.json()
    except Exception as e:
        raise ValueError(f"Invalid JSON from {url}: {e}") from e


def validate_ip_address(ip: str) -> bool:
    """Basic IPv4 validation; empty is 'ok' meaning use public IP."""
    if not ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def get_public_ip() -> str:
    """Get public IP via multiple fallbacks."""
    services = [
        "https://api.ipify.org?format=json",
        "https://httpbin.org/ip",
        "http://ip-api.com/json/",
    ]
    for svc in services:
        try:
            data = safe_get_json(svc, timeout=6)
            if isinstance(data, dict):
                if "ip" in data:
                    return data["ip"]
                if "origin" in data:
                    return data["origin"].split(",")[0].strip()
                if "query" in data:
                    return data["query"]
        except Exception:
            continue
    raise RuntimeError("All IP detection services failed")


def check_vpn_status(ip_address: str, geo_data: dict) -> dict:
    vpn_indicators = {
        "is_vpn": False,
        "confidence": "Low",
        "indicators": [],
        "risk_score": 0,
        "debug_info": [],
    }

    try:
        isp = str(geo_data.get("isp", "")).lower()
        org = str(geo_data.get("org", "")).lower()
        as_info = str(geo_data.get("as", "")).lower()
        country = str(geo_data.get("country", "")).lower()

        # --------------------
        # Reverse DNS check
        # --------------------
        try:
            hostname = socket.gethostbyaddr(ip_address)[0].lower()
            vpn_indicators["debug_info"].append(f"RDNS: {hostname}")
            if any(v in hostname for v in ["vpn", "cloud", "vps", "host", "server"]):
                vpn_indicators["indicators"].append(f"Suspicious RDNS: {hostname}")
                vpn_indicators["risk_score"] += 20
        except Exception:
            vpn_indicators["debug_info"].append("RDNS lookup failed")

        # --------------------
        # Known provider keywords
        # --------------------
        vpn_keywords = [
            "vpn", "proxy", "tunnel", "wireguard", "openvpn",
            "nordvpn", "expressvpn", "surfshark", "cyberghost",
            "m247", "leaseweb", "choopa", "colo", "datacamp", "g-core",
            "digitalocean", "ovh", "hetzner", "linode", "aws", "azure", "google"
        ]
        for kw in vpn_keywords:
            if kw in isp or kw in org or kw in as_info:
                vpn_indicators["indicators"].append(f'Match keyword "{kw}"')
                vpn_indicators["risk_score"] += 15

        # --------------------
        # Bogon / private range
        # --------------------
        private_prefixes = ("10.", "172.16.", "192.168.", "127.")
        if ip_address.startswith(private_prefixes):
            vpn_indicators["indicators"].append("Private/Bogon IP – suspicious for VPN masking")
            vpn_indicators["risk_score"] += 25

        # --------------------
        # Lightweight port check
        # --------------------
        common_ports = [1194, 1701, 500, 4500, 1723, 51820]  # OpenVPN, L2TP, IKEv2, PPTP, WireGuard
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip_address, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        if open_ports:
            vpn_indicators["indicators"].append(f"Open VPN-related ports: {open_ports}")
            vpn_indicators["risk_score"] += 25

        # --------------------
        # Risk evaluation
        # --------------------
        score = max(0, min(100, vpn_indicators["risk_score"]))
        vpn_indicators["risk_score"] = score
        if score >= 70:
            vpn_indicators.update({"is_vpn": True, "confidence": "Very High"})
        elif score >= 50:
            vpn_indicators.update({"is_vpn": True, "confidence": "High"})
        elif score >= 30:
            vpn_indicators.update({"is_vpn": True, "confidence": "Medium"})
        elif score >= 15:
            vpn_indicators.update({"is_vpn": True, "confidence": "Low"})
    except Exception as e:
        vpn_indicators["indicators"].append(f"Error in VPN detection: {e}")
        vpn_indicators["debug_info"].append(str(e))

    return vpn_indicators


def measure_network_speed() -> dict:
    """Run speed test safely. Returns friendly strings and debug info."""
    if speedtest is None:
        return {
            "download_speed": "N/A",
            "upload_speed": "N/A",
            "ping": "N/A",
            "success": False,
            "error": "speedtest-cli not installed. pip install speedtest-cli",
            "debug_info": [],
        }
    try:
        stest = speedtest.Speedtest(secure=True)
        # Avoid KeyError if config shape differs
        try:
            client = stest.config.get("client")
            if isinstance(client, dict):
                client["useragent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        except Exception:
            pass

        stest.get_servers()
        stest.get_best_server()
        download = stest.download() / 1_000_000.0
        upload = stest.upload() / 1_000_000.0
        ping = stest.results.ping

        server = stest.results.server or {}
        sponsor = server.get("sponsor", "Unknown")
        name = server.get("name", "Unknown")
        distance = server.get("d", None)
        dist_txt = f"{float(distance):.2f} km" if isinstance(distance, (int, float, str)) else "n/a"

        return {
            "download_speed": f"{download:.2f} Mbps",
            "upload_speed": f"{upload:.2f} Mbps",
            "ping": f"{float(ping):.2f} ms" if ping is not None else "N/A",
            "success": True,
            "error": None,
            "debug_info": [f"Server: {sponsor} ({name})", f"Distance: {dist_txt}"],
        }
    except speedtest.ConfigRetrievalError:
        return {
            "download_speed": "N/A",
            "upload_speed": "N/A",
            "ping": "N/A",
            "success": False,
            "error": "Speedtest config failed (servers unavailable)",
            "debug_info": ["Try again later"],
        }
    except speedtest.NoMatchedServers:
        return {
            "download_speed": "N/A",
            "upload_speed": "N/A",
            "ping": "N/A",
            "success": False,
            "error": "No speedtest servers matched in your region",
            "debug_info": [],
        }
    except Exception as e:
        emsg = str(e)
        if "403" in emsg or "Forbidden" in emsg:
            return {
                "download_speed": "N/A",
                "upload_speed": "N/A",
                "ping": "N/A",
                "success": False,
                "error": "Speedtest temporarily blocked (HTTP 403)",
                "debug_info": ["Retry in a few minutes"],
            }
        if "timeout" in emsg.lower():
            return {
                "download_speed": "N/A",
                "upload_speed": "N/A",
                "ping": "N/A",
                "success": False,
                "error": "Speedtest timed out",
                "debug_info": [],
            }
        return {
            "download_speed": "N/A",
            "upload_speed": "N/A",
            "ping": "N/A",
            "success": False,
            "error": f"Speedtest error: {e}",
            "debug_info": [],
        }


def get_weather_description(code: int) -> str:
    weather_codes = {
        0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
        45: "Fog", 48: "Depositing rime fog", 51: "Light drizzle", 53: "Moderate drizzle",
        55: "Dense drizzle", 56: "Light freezing drizzle", 57: "Dense freezing drizzle",
        61: "Slight rain", 63: "Moderate rain", 65: "Heavy rain",
        66: "Light freezing rain", 67: "Heavy freezing rain",
        71: "Slight snow fall", 73: "Moderate snow fall", 75: "Heavy snow fall",
        77: "Snow grains", 80: "Slight rain showers", 81: "Moderate rain showers",
        82: "Violent rain showers", 85: "Slight snow showers", 86: "Heavy snow showers",
        95: "Thunderstorm", 96: "Thunderstorm with slight hail", 99: "Thunderstorm with heavy hail",
    }
    return weather_codes.get(int(code) if code is not None else 0, f"Unknown (code {code})")


# ----------------------------
# UI helpers
# ----------------------------
def display_results(results: dict):
    if not results:
        return

    try:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📍 IP Information")
            st.write(f"**IP Address:** {results.get('ip_address','N/A')}")
            st.write(f"**ISP:** {results.get('isp','N/A')}")
            st.write(f"**Organization:** {results.get('org','N/A')}")
            st.write(f"**AS:** {results.get('as_info','N/A')}")

        with col2:
            st.subheader("🌐 Location Details")
            st.write(f"**City:** {results.get('city','N/A')}")
            st.write(f"**Region:** {results.get('region','N/A')}")
            st.write(f"**Country:** {results.get('country','N/A')}")
            st.write(f"**ZIP Code:** {results.get('zip_code','N/A')}")
            lat = results.get("lat"); lon = results.get("lon")
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                st.write(f"**Coordinates:** {lat:.4f}, {lon:.4f}")
            else:
                st.write("**Coordinates:** N/A")

        st.subheader("📡 Network Performance")
        network = results.get("network", {})
        speed = (network or {}).get("speed", {})
        if speed.get("success"):
            ncol1, ncol2 = st.columns(2)
            with ncol1:
                st.metric("⬇️ Download Speed", speed.get("download_speed", "N/A"))
                st.metric("⬆️ Upload Speed", speed.get("upload_speed", "N/A"))
            with ncol2:
                st.metric("🏓 Ping", speed.get("ping", "N/A"))
        else:
            if speed:
                st.warning(f"⚠️ Speed test: {speed.get('error','Unavailable')}")

        dbg = speed.get("debug_info") or []
        if dbg:
            with st.expander("🔍 Network Test Debug Info", expanded=False):
                for x in dbg:
                    st.write(f"• {x}")

        # VPN
        st.subheader("🔒 VPN/Proxy Analysis")
        vpn_info = results.get("vpn_status") or {}
        if vpn_info:
            if vpn_info.get("is_vpn"):
                conf = vpn_info.get("confidence", "Unknown")
                if conf in ("Very High", "High"):
                    st.error(f"🚨 VPN/Proxy Detected (Confidence: {conf})")
                elif conf == "Medium":
                    st.warning(f"⚠️ Likely VPN/Proxy (Confidence: {conf})")
                else:
                    st.info(f"ℹ️ Possible VPN/Proxy (Confidence: {conf})")
            else:
                st.success("✅ Direct Connection — No VPN/Proxy detected")

            score = int(vpn_info.get("risk_score", 0))
            risk_emoji = "🔴" if score >= 50 else ("🟡" if score >= 25 else "🟢")
            st.write(f"**Risk Score:** {risk_emoji} {score}/100")

            inds = vpn_info.get("indicators") or []
            if inds:
                st.write("**Detection Indicators:**")
                for i in inds:
                    st.write(f"• {i}")

            dinfo = vpn_info.get("debug_info") or []
            if dinfo:
                with st.expander("🔧 Debug Information", expanded=False):
                    for d in dinfo:
                        st.write(f"• {d}")

            st.info("💡 VPN detection is heuristic and may not be 100% accurate.")
        else:
            st.info("⚠️ VPN status not available")

        # Map
        st.subheader("🗺️ Location on Map")
        try:
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                m = folium.Map(location=[lat, lon], zoom_start=12, tiles="OpenStreetMap")

                popup_text = f"""
                <b>{results.get('city','Unknown')}, {results.get('country','Unknown')}</b><br>
                IP: {results.get('ip_address','N/A')}<br>
                ISP: {results.get('isp','N/A')}<br>
                Coordinates: {lat:.4f}, {lon:.4f}
                """

                folium.Marker(
                    [lat, lon],
                    popup=folium.Popup(popup_text, max_width=300),
                    tooltip="Click for details",
                    icon=folium.Icon(color="red", icon="info-sign"),
                ).add_to(m)

                folium.Circle(
                    [lat, lon],
                    radius=1000,
                    color="blue",
                    fill=True,
                    fill_color="blue",
                    fill_opacity=0.2,
                    popup="Approximate location area",
                ).add_to(m)

                st_folium(m, width=700, height=500, key=f"map_{results.get('ip_address','unknown')}")
            else:
                st.info("Location coordinates unavailable; map skipped.")
        except Exception as e:
            st.error(f"❌ Error creating map: {e}")

        # Weather
        st.subheader("🌤️ Current Weather")
        weather = results.get("weather")
        if weather:
            wcol1, wcol2, wcol3 = st.columns(3)
            with wcol1:
                st.metric("🌡️ Temperature", weather.get("temp", "N/A"))
                st.metric("💧 Humidity", weather.get("humidity", "N/A"))
            with wcol2:
                st.metric("🤒 Feels Like", weather.get("apparent_temp", "N/A"))
                st.metric("🌧️ Precipitation", weather.get("precipitation", "N/A"))
            with wcol3:
                st.metric("💨 Wind Speed", weather.get("wind_speed", "N/A"))
                st.write(f"**🌤️ Conditions:** {weather.get('description','N/A')}")
        else:
            st.warning("⚠️ Weather data not available")

        # Webcams
        webcams = results.get("webcams") or []
        webcam_message = results.get("webcam_message")
        if webcams:
            st.subheader("📹 Nearby Webcams")
            st.success(f"Found {len(webcams)} webcams within 50km")
            for i, cam in enumerate(webcams):
                title = cam.get("title", f"Webcam {i+1}")
                with st.expander(f"📷 {title}", key=f"webcam_{i}_{results.get('ip_address','unknown')}"):
                    if cam.get("image_url"):
                        st.image(cam["image_url"], caption=title, use_column_width=True)
                    if cam.get("location"):
                        st.write(f"**Location:** {cam['location']}")
                    if cam.get("embed_code"):
                        st.write("**Day Timelapse:**")
                        st.components.v1.html(cam["embed_code"], height=300)
        elif webcam_message:
            st.info(webcam_message)

    except Exception as e:
        st.error(f"❌ Error displaying results: {e}")


# ----------------------------
# Session state
# ----------------------------
for key, default in [
    ("tracking_results", None),
    ("last_tracked_ip", None),
    ("show_results", False),
    ("ip_input", ""),
    ("current_public_ip", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ----------------------------
# Main UI
# ----------------------------
st.title("🌍 IP Address Location Tracker")

with st.sidebar:
    st.title("ℹ️ About")
    st.markdown(
        "Track the geolocation of an IP, check for VPN/proxy signals, measure network speed, "
        "and discover nearby webcams (Windy API key optional)."
    )
    st.markdown("---")
    st.subheader("🚀 Quick Actions")

    if st.button("🌐 Get My IP", key="get_ip_btn"):
        try:
            with st.spinner("Getting your IP address..."):
                public_ip = get_public_ip()
                st.session_state.current_public_ip = public_ip
                st.session_state.ip_input = public_ip
                st.rerun()
        except Exception as e:
            st.error(f"❌ Error getting IP: {e}")

    if st.session_state.get("current_public_ip"):
        st.info(f"🌐 **Your Current IP:** {st.session_state.current_public_ip}")

    # Manual weather coords (optional, replaces brittle browser geolocation hack)
    st.markdown("---")
    st.subheader("📍 Optional Weather Coordinates")
    manual_lat = st.text_input("Latitude (optional)", value="", key="manual_lat")
    manual_lon = st.text_input("Longitude (optional)", value="", key="manual_lon")

    if st.button("🔒 Get VPN Status", key="get_vpn_btn"):
        try:
            with st.spinner("Checking VPN status..."):
                current_ip = (st.session_state.get("ip_input") or "").strip() or get_public_ip()
                geo_data = safe_get_json(f"http://ip-api.com/json/{current_ip}", timeout=10)
                if geo_data.get("status") == "success":
                    vpn_status = check_vpn_status(current_ip, geo_data)
                    if vpn_status["is_vpn"]:
                        conf = vpn_status["confidence"]
                        if conf in ("Very High", "High"):
                            st.error(f"🚨 VPN/Proxy Detected (Confidence: {conf})")
                        elif conf == "Medium":
                            st.warning(f"⚠️ Likely VPN/Proxy (Confidence: {conf})")
                        else:
                            st.info(f"ℹ️ Possible VPN/Proxy (Confidence: {conf})")
                    else:
                        st.success("✅ Direct Connection — No VPN/Proxy detected")
                    st.write(f"Risk Score: {vpn_status['risk_score']}/100")
                else:
                    st.error(f"❌ Could not check VPN status: {geo_data.get('message','Unknown error')}")
        except requests.exceptions.RequestException as e:
            st.error(f"❌ Network error checking VPN: {e}")
        except Exception as e:
            st.error(f"❌ Error checking VPN: {e}")

    if st.button("🌤️ Get Weather Report", key="get_weather_btn"):
        try:
            with st.spinner("Getting weather data..."):
                lat, lon = None, None

                # Use manual coords if provided
                try:
                    if manual_lat.strip() and manual_lon.strip():
                        lat = float(manual_lat.strip())
                        lon = float(manual_lon.strip())
                        st.info("📍 Using manually provided coordinates.")
                except Exception:
                    st.warning("Manual coordinates invalid; falling back to IP-based location.")

                if lat is None or lon is None:
                    current_ip = (st.session_state.get("ip_input") or "").strip() or get_public_ip()
                    geo = safe_get_json(f"http://ip-api.com/json/{current_ip}", timeout=10)
                    if geo.get("status") == "success":
                        lat = geo.get("lat"); lon = geo.get("lon")
                        city = geo.get("city", "Unknown")
                        region = geo.get("regionName", "Unknown")
                        country = geo.get("country", "Unknown")
                        st.info(f"📍 Using IP-based location: {city}, {region}, {country}")
                    else:
                        st.error(f"❌ Could not determine location: {geo.get('message','Unknown error')}")
                        st.stop()

                weather_url = (
                    "https://api.open-meteo.com/v1/forecast"
                    f"?latitude={lat}&longitude={lon}"
                    "&current=temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m"
                    "&timezone=auto"
                )
                w = safe_get_json(weather_url, timeout=10)
                if isinstance(w, dict) and "current" in w and isinstance(w["current"], dict):
                    cur = w["current"]
                    weather_desc = get_weather_description(cur.get("weather_code", 0))
                    st.success("🌤️ **Current Weather:**")
                    st.write(f"🌡️ **Temperature:** {cur.get('temperature_2m','N/A')}°C")
                    st.write(f"🤒 **Feels Like:** {cur.get('apparent_temperature','N/A')}°C")
                    st.write(f"💧 **Humidity:** {cur.get('relative_humidity_2m','N/A')}%")
                    st.write(f"💨 **Wind Speed:** {cur.get('wind_speed_10m','N/A')} km/h")
                    st.write(f"☁️ **Conditions:** {weather_desc}")
                else:
                    st.error("❌ Weather data not available")
        except requests.exceptions.RequestException as e:
            st.error(f"❌ Network error getting weather: {e}")
        except Exception as e:
            st.error(f"❌ Error getting weather: {e}")

# ----------------------------
# Inputs
# ----------------------------
ip_address = st.text_input(
    "Enter IP Address (leave blank for your public IP):",
    key="ip_input",
)

windy_api_key = st.text_input(
    "Windy API Key (for webcams, optional):",
    type="password",
    key="windy_key",
    help="Get a free API key at https://api.windy.com/keys",
)

# Buttons
button_col1, button_col2 = st.columns([1, 1])
with button_col1:
    track_button = st.button("🔍 Track Location", key="track_btn")
with button_col2:
    if st.session_state.show_results and st.session_state.tracking_results:
        if st.button("🗑️ Clear Results", key="clear_btn"):
            st.session_state.tracking_results = None
            st.session_state.last_tracked_ip = None
            st.session_state.show_results = False
            st.rerun()

# ----------------------------
# Tracking logic
# ----------------------------
if track_button:
    if ip_address and not validate_ip_address(ip_address):
        st.error("❌ Invalid IP address format. Please enter a valid IPv4 address.")
    else:
        current_ip = (ip_address or "").strip()
        if not current_ip:
            try:
                with st.spinner("Getting your public IP address..."):
                    current_ip = get_public_ip()
                    st.info(f"ℹ️ Using your public IP: {current_ip}")
            except Exception as e:
                st.error(f"❌ Error fetching public IP: {e}")
                st.stop()

        need_new = (
            not st.session_state.tracking_results
            or st.session_state.last_tracked_ip != current_ip
        )
        if need_new:
            try:
                with st.spinner("Fetching location data..."):
                    geo_data = safe_get_json(f"http://ip-api.com/json/{current_ip}", timeout=10)
                    if geo_data.get("status") == "fail":
                        st.error(f"❌ Error: {geo_data.get('message','Unknown error')}")
                        st.stop()

                    lat = geo_data.get("lat"); lon = geo_data.get("lon")
                    if lat is None or lon is None:
                        st.error("❌ Unable to determine coordinates for this IP address.")
                        st.stop()

                    results = {
                        "ip_address": current_ip,
                        "lat": lat,
                        "lon": lon,
                        "city": geo_data.get("city", "Unknown"),
                        "region": geo_data.get("regionName", "Unknown"),
                        "country": geo_data.get("country", "Unknown"),
                        "zip_code": geo_data.get("zip", "N/A"),
                        "isp": geo_data.get("isp", "Unknown"),
                        "org": geo_data.get("org", "N/A"),
                        "as_info": geo_data.get("as", "N/A"),
                        "weather": None,
                        "webcams": [],
                        "webcam_message": None,
                        "vpn_status": None,
                        "network": None,
                    }

                # VPN status
                try:
                    with st.spinner("Checking VPN/Proxy status..."):
                        results["vpn_status"] = check_vpn_status(current_ip, geo_data)
                except Exception as e:
                    st.warning(f"⚠️ Could not check VPN status: {e}")
                    results["vpn_status"] = {
                        "is_vpn": False, "confidence": "Unknown",
                        "indicators": [f"VPN check failed: {e}"], "risk_score": 0,
                    }

                # Network speed
                try:
                    with st.spinner("Measuring network performance..."):
                        results["network"] = {"speed": measure_network_speed()}
                except Exception as e:
                    st.warning(f"⚠️ Could not measure network performance: {e}")
                    results["network"] = {
                        "speed": {
                            "download_speed": "N/A",
                            "upload_speed": "N/A",
                            "ping": "N/A",
                            "success": False,
                            "error": str(e),
                            "debug_info": [f"Network performance error: {e}"],
                        }
                    }

                # Weather
                try:
                    with st.spinner("Fetching weather data..."):
                        weather_url = (
                            "https://api.open-meteo.com/v1/forecast"
                            f"?latitude={lat}&longitude={lon}"
                            "&current=temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m"
                            "&timezone=auto"
                        )
                        weather_data = safe_get_json(weather_url, timeout=10)
                        cur = weather_data.get("current") if isinstance(weather_data, dict) else None
                        if isinstance(cur, dict):
                            weather_desc = get_weather_description(cur.get("weather_code", 0))
                            results["weather"] = {
                                "temp": f"{cur.get('temperature_2m','N/A')}°C" if cur.get("temperature_2m") is not None else "N/A",
                                "humidity": f"{cur.get('relative_humidity_2m','N/A')}%" if cur.get("relative_humidity_2m") is not None else "N/A",
                                "apparent_temp": f"{cur.get('apparent_temperature','N/A')}°C" if cur.get("apparent_temperature") is not None else "N/A",
                                "precipitation": f"{cur.get('precipitation', 0)} mm",
                                "wind_speed": f"{cur.get('wind_speed_10m','N/A')} km/h" if cur.get("wind_speed_10m") is not None else "N/A",
                                "description": weather_desc,
                            }
                        else:
                            st.warning("⚠️ Weather data format unexpected")
                except requests.exceptions.RequestException as e:
                    st.warning(f"⚠️ Could not fetch weather data (network): {e}")
                except Exception as e:
                    st.warning(f"⚠️ Could not fetch weather data: {e}")

                # Webcams (Windy)
                key = (windy_api_key or "").strip()
                if key:
                    try:
                        with st.spinner("Searching for nearby webcams..."):
                            headers = {"x-windy-key": key}
                            params = {"show": "webcams:location,image,player"}
                            webcam_url = f"https://api.windy.com/api/webcams/v3/list/nearby={lat},{lon},50"
                            webcam_data = safe_get_json(webcam_url, timeout=15, headers=headers, params=params)
                            if isinstance(webcam_data, dict) and webcam_data.get("status") == "OK":
                                cams = (webcam_data.get("result") or {}).get("webcams") or []
                                for i, cam in enumerate(cams[:5]):
                                    if not isinstance(cam, dict):
                                        continue
                                    img = (((cam.get("image") or {}).get("current") or {}).get("preview"))
                                    loc = cam.get("location") or {}
                                    player = (cam.get("player") or {}).get("day") or {}
                                    results["webcams"].append({
                                        "title": cam.get("title", f"Webcam {i+1}"),
                                        "image_url": img,
                                        "location": f"{loc.get('city','Unknown')}, {loc.get('region','Unknown')}",
                                        "embed_code": player.get("embed"),
                                    })
                            else:
                                msg = webcam_data.get("message", "Unknown error") if isinstance(webcam_data, dict) else "Invalid response"
                                results["webcam_message"] = f"⚠️ Webcam API response: {msg}"
                    except requests.exceptions.RequestException as e:
                        results["webcam_message"] = f"❌ Network error fetching webcams: {e}"
                    except Exception as e:
                        results["webcam_message"] = f"❌ Error fetching webcams: {e}"
                else:
                    results["webcam_message"] = "💡 Tip: Provide a Windy API key to fetch nearby webcams."

                st.session_state.tracking_results = results
                st.session_state.last_tracked_ip = current_ip
                st.session_state.show_results = True
                st.success("✅ Location data fetched successfully!")
            except requests.exceptions.Timeout:
                st.error("❌ Request timed out. Check your internet connection and try again.")
            except requests.exceptions.RequestException as e:
                st.error(f"❌ Network error: {e}")
            except ValueError as e:
                st.error(f"❌ Response parsing error: {e}")
            except Exception as e:
                st.error(f"❌ Unexpected error: {e}")
        else:
            st.session_state.show_results = True
            st.info("ℹ️ Showing cached results for this IP address.")

# ----------------------------
# Results
# ----------------------------
if st.session_state.show_results and st.session_state.tracking_results:
    st.markdown("---")
    st.subheader(f"📊 Results for IP: {st.session_state.tracking_results.get('ip_address','N/A')}")
    display_results(st.session_state.tracking_results)

# ----------------------------
# Footer
# ----------------------------
st.markdown("---")
try:
    wat_tz = pytz.timezone("Africa/Lagos")
    current_time = datetime.now(wat_tz)
    formatted_time = current_time.strftime("%I:%M %p WAT on %A, %B %d, %Y")
    st.markdown(f"**Current Time:** {formatted_time}")
except Exception:
    current_time = datetime.utcnow()
    formatted_time = current_time.strftime("%I:%M %p UTC on %A, %B %d, %Y")
    st.markdown(f"**Current Time:** {formatted_time}")

st.markdown("**Note:** IP geolocation is approximate and may vary.")
st.markdown("**Privacy:** This app does not store IPs or locations.")
st.markdown("**Network Tests:** Results depend on server availability.")
st.markdown("Developed by Hacker Joe.")
