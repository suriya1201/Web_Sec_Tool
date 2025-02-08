def make_http_request(url):
    import requests
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error making HTTP request: {e}")
        return None

def parse_html(html_content):
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup

def extract_links(soup):
    return [a['href'] for a in soup.find_all('a', href=True)]