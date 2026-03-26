import requests

def expand_url(short_url):
    try:
        # Send a HEAD request (faster, no content download)
        response = requests.head(short_url, allow_redirects=True, timeout=10)
        return response.url
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
