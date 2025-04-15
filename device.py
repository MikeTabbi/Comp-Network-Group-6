import requests

device_id = "device_001"
response = requests.post("http://127.0.0.1:5000/register", json={"device_id": device_id})

print(response.json())
