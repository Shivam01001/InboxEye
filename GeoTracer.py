import requests
import folium
import os

class GeoTracer:
    def __init__(self):
        self.ip_data = {}
        # Simple IP info mapping
        self.api_url = "http://ip-api.com/json/"

    def trace_ips(self, ip_list):
        """Map IPs to coordinates and info."""
        traced_path = []
        for index, ip in enumerate(ip_list):
            if ip in self.ip_data:
                # Still append the cloned info
                info = dict(self.ip_data[ip])
                if index == 0:
                    info['isp'] = "Sender Origin (" + str(info.get('isp', 'Unknown')) + ")"
                traced_path.append(info)
                continue
                
            try:
                # Add delay or caching as IP-API enforces 45 calls per minute limit
                response = requests.get(f"{self.api_url}{ip}", timeout=5)
                data = response.json()
                if data.get("status") == "success":
                    info = {
                        "ip": ip,
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "city": data.get("city"),
                        "country": data.get("country"),
                        "isp": data.get("isp")
                    }
                    self.ip_data[ip] = info
                    
                    track_info = dict(info)
                    if index == 0:
                        track_info['isp'] = "Sender Origin (" + str(track_info.get('isp', 'Unknown')) + ")"
                        
                    traced_path.append(track_info)
                else:
                    print(f"Failed to trace {ip}: {data.get('message')}")
            except Exception as e:
                print(f"Error fetching IP {ip}: {e}")
                
        return traced_path

    def get_current_location(self):
        """Fetch the public IP and geolocation of the current device as the final destination."""
        try:
            response = requests.get(self.api_url, timeout=5)
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "city": data.get("city"),
                    "country": data.get("country"),
                    "isp": "Recipient Destination (" + str(data.get("isp", "Unknown")) + ")"
                }
        except Exception as e:
            print(f"Error fetching destination location: {e}")
        return None

    def generate_map(self, traced_path, threat_data=None, save_dir=None):
        """Generate a Folium HTML map with markers for the trace."""
        if not threat_data:
            threat_data = {}

        save_dir = save_dir or os.getcwd()
        map_file = os.path.join(save_dir, 'routemap.html')

        if not traced_path:
            # Default to a generic map center if no route
            mail_map = folium.Map(location=[0, 0], zoom_start=2)
            mail_map.save(map_file)
            return map_file

        # Center map on the first hop originally
        start_loc = (traced_path[0]["lat"], traced_path[0]["lon"])
        mail_map = folium.Map(location=start_loc, zoom_start=3, tiles='CartoDB dark_matter')

        coordinates_list = []
        seen_coords = set()

        for i, hop in enumerate(traced_path):
            ip = hop['ip']
            lat, lon = hop.get('lat'), hop.get('lon')
            
            # If coordinates are missing (like for internal IPs), default to 0.0, 0.0 (Null Island)
            if not lat and not lon:
                lat = 0.0
                lon = 0.0
                
            # Offset overlapping markers so intermediate hops aren't perfectly hidden
            while (lat, lon) in seen_coords:
                lat = lat + 1.0
                lon = lon + 1.0
                
            seen_coords.add((lat, lon))
            coordinates_list.append((lat, lon))
            
            # Look up threat score for color coding
            score = threat_data.get(ip, {}).get('abuseConfidenceScore', 0)
            
            # Simple color logic based on report counts or score
            marker_color = 'red' if score > 10 else 'green'
            icon_type = 'warning' if score > 10 else 'info-sign'
            
            popup_html = f"<b>Hop {i+1}: {ip}</b><br>{hop['city']}, {hop['country']}<br>ISP: {hop['isp']}<br>Risk Score: {score}"
            
            folium.Marker(
                location=[lat, lon],
                popup=folium.Popup(popup_html, max_width=300),
                icon=folium.Icon(color=marker_color, icon=icon_type)
            ).add_to(mail_map)

        # Draw lines to form a path
        if len(coordinates_list) > 1:
            folium.PolyLine(
                coordinates_list,
                weight=2,
                color='blue',
                opacity=0.8,
                dash_array='5'
            ).add_to(mail_map)

        mail_map.save(map_file)
        return map_file
