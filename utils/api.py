# Define session object to handle all https requests
# Handle rate-limit and server errors
from typing import Any, Dict, List, Optional, Set
from requests.exceptions import HTTPError, Timeout, RequestException
from requests.adapters import HTTPAdapter
import urllib3
from urllib3.util.retry import Retry
import requests
from core.base import ScriptContext
import json

from utils.process_data import process_data
from utils.display import get_global_color_scheme
from utils.app_lifecycle import exit_now

# Disable SSL self-signed cert warnings, comment out line below if Infoblox
# deployment uses proper certificate
urllib3.disable_warnings()

retries = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"],
    backoff_factor=2,
)

adapter = HTTPAdapter(max_retries=retries, pool_connections=10)
session = requests.Session()
session.mount("https://", adapter)
session.headers.update({"Content-Type": "application/json"})


def make_api_call(ctx: ScriptContext, uri: str) -> requests.Response:
    """
    Performs Infoblox API requests with intelligent error handling.

    - Treats 400 errors as non-fatal (e.g., "not found").
    - Treats 401 as a fatal authentication error.
    - Retries on 5xx server errors.
    - Exits on connection errors.
    """
    logger = ctx.logger
    endpoint = ctx.cfg["api_endpoint"]
    full_url = f"{endpoint}{uri}"

    logger.info(f"Performing API request - URL: {full_url}")
    response = requests.Response()
    try:
        response = session.get(full_url, verify=False)
        # Check for specific, non-fatal client errors first
        if response.status_code == 400:
            # This is often "not found". Log it for debugging but don't treat as a hard error.
            logger.debug(f"API Info (400 - Bad Request): {response.text} for URL: {full_url}")
            # Return the response object so the caller can see the 400 status
            return response

        if response.status_code == 404:
            # A true "Not Found" is also not a failure of our script.
            logger.info(f"API Info (404 - Not Found) for URL: {full_url}")
            return response

        # Check for fatal authentication error
        if response.status_code == 401:
            logger.error(f"FATAL API Error (401 - Unauthorized): {response.text}")
            exit_now(ctx, exit_code=1, message='Authentication error - verify credentials.')

        # For all other 4xx and 5xx errors, raise an exception to be caught below.
        response.raise_for_status()

    except (Timeout, ConnectionError) as e:
        logger.error(f"API Connection Error for URL {full_url}: {e}")
        # Connection errors are usually fatal for a CLI tool, as the endpoint is unavailable.
        exit_now(ctx, exit_code=1, message=f"API Connection Error - unable to reach {endpoint}")

    except HTTPError as e:
        # This will now only catch the errors we didn't handle above (e.g., 403, 500, 503).
        status_code = e.response.status_code
        text = e.response.text
        logger.error(f"Unhandled API HTTP Error - {status_code}: {text}")
        # We return the failed response object for the caller to handle.
        return e.response

    except RequestException as e:
        # Catch any other requests-related exceptions
        logger.error(f"Generic API Request Error for URL {full_url}: {e}")
        return response  # Return the initialized (empty) response

    # Final check for valid JSON in successful responses
    if response.ok:
        try:
            response.json()
        except json.JSONDecodeError:
            logger.error(f"API Error - Failed to parse JSON from a successful (2xx) response. Content: {response.text}")

    return response


def do_fancy_request(
    ctx: ScriptContext,
    message: str,
    uri: str,
    spinner: Optional[str] = "dots12",
) -> Optional[bytes]:
    """
    Prepares shows message, spinner and performs make_api_call
    Validates response status
    """
    def execute_request() -> Optional[bytes]:
        response = make_api_call(ctx, uri)
        if response.ok:
            return response.content
        return None

    if spinner:
        with ctx.console.status(status=message, spinner=spinner):
            return execute_request()
    else:
        return execute_request()


# Function to selectively encode the regex pattern for Infoblox WAPI
def selective_url_encode(pattern: str) -> str:
    # Characters that need to be URL-encoded
    chars_to_encode = {"%", ";", "/", "?", ":", "@", "&", "=", "+", "$", ",", " "}
    encoded_pattern = ""
    for char in pattern:
        if char in chars_to_encode:
            encoded_pattern += f"%{ord(char):02X}"  # URL-encode the character
        else:
            encoded_pattern += char  # Leave the character as-is
    return encoded_pattern


def fetch_network_data(ctx: ScriptContext, search_term: str, keyword: bool = False) -> Dict[str, List[Dict[str, str]]]:
    """
    Fetches and processes IPv4 and IPv6 network data based on a search term.
    Merges results, removes duplicates, and returns the processed data.
    """

    colors = get_global_color_scheme(ctx.cfg)
    search_type = ''

    if not keyword:
        # Build regex pattern for site code search
        padded_search_term = rf'^[^;]+;\s*{search_term}\s*;'
        encoded_pattern = selective_url_encode(padded_search_term)
        search_type = f"location_{search_term}"
    else:
        encoded_pattern = selective_url_encode(search_term)
        search_type = "location_keyword"

    uri_ipv4 = f"network?comment:~={encoded_pattern}&_max_results=1000"
    uri_ipv6 = f"ipv6network?comment:~={encoded_pattern}&_max_results=1000"

    # Fetch IPv4 data
    data_ipv4 = do_fancy_request(
        ctx,
        message=f"[{colors['description']}]Fetching IPv4 data for [{colors['header']}]{search_term.upper()}[/]...[/]",
        uri=uri_ipv4,
    )

    # Fetch IPv6 data
    data_ipv6 = do_fancy_request(
        ctx,
        message=f"[{colors['description']}]Fetching IPv6 data for [{colors['header']}]{search_term.upper()}[/]...[/]",
        uri=uri_ipv6,
    )

    # Process data
    processed_data_ipv4: Dict[str, Any] = process_data(
        ctx, type=search_type, content=data_ipv4
    ) if data_ipv4 else {}

    processed_data_ipv6: Dict[str, Any] = process_data(
        ctx, type=search_type, content=data_ipv6
    ) if data_ipv6 else {}

    # Merge and deduplicate
    united_locations = processed_data_ipv4.get('location', []) + processed_data_ipv6.get('location', [])
    unique_networks: Set[str] = set()
    merged_locations: List[Dict[str, str]] = []

    for item in united_locations:
        network = item['network']
        if network not in unique_networks:
            unique_networks.add(network)
            merged_locations.append(item)

    return {'location': merged_locations}
