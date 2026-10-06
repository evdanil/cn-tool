# Copyright 2024 - Evgeny Danilchenko evdanil@gmail.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from typing import Dict, List, Optional

import ldap3
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.exceptions import (
    LDAPException,
    LDAPResponseTimeoutError,
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
    LDAPSocketSendError,
)

# It's good practice to request only the attributes you need instead of '*'
DEFAULT_ATTRS: List[str] = [
    "name",
    "siteObject",
    "location",
    "description",
    "whenCreated",
    "whenChanged"
]

# Can be overridden in config file if needed.
DEFAULT_SEARCH_BASE: str = 'CN=Subnets,CN=Sites,CN=Configuration,DC=domain,DC=com'
DEFAULT_OPERATION_TIMEOUT: int = 10

RETRYABLE_EXCEPTIONS = (
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
    LDAPSocketSendError,
    LDAPResponseTimeoutError,
)


def init_ad_link(
    logger: logging.Logger,
    user: str,
    password: str,
    ldap_uri: str,
    operation_timeout: int = DEFAULT_OPERATION_TIMEOUT,
) -> Optional[ldap3.Connection]:
    """
    Initializes and binds a connection to an Active Directory server.

    Args:
        logger: A configured logger instance.
        user: The username for authentication (e.g., 'user@domain.com').
        password: The user's password.
        ldap_uri: The URI of the LDAP server (e.g., 'ldap://ad.domain.com').

    Returns:
        An ldap3.Connection object if successful, otherwise None.
    """
    if not user or not ldap_uri or not password:
        logger.warning("AD username, password, or LDAP URI is missing. Cannot initiate connection.")
        return None

    server = ldap3.Server(ldap_uri, get_info=ldap3.ALL)
    try:
        conn = ldap3.Connection(
            server,
            user=user,
            password=password,
            auto_bind=True,
            read_only=True,
            receive_timeout=operation_timeout,
        )

        # start_tls() is often used with ldap://. If you use ldaps:// (port 636),
        # this is not needed and might even fail. Adjust based on your server config.
        # For simplicity, we can attempt it and log a warning if it fails.
        if 'ldaps' not in ldap_uri.lower():
            conn.start_tls()

        if conn.bound:
            logger.info(f"Successfully connected and bound to AD server: {ldap_uri}")
            return conn
        else:
            logger.error(f"Failed to bind to AD server: {conn.result}")
            return None
    except LDAPException as e:
        logger.error(f"An LDAP error occurred while trying to connect: {e}")
        return None


def get_ad_subnet_info(
    logger: logging.Logger,
    ldap_link: ldap3.Connection,
    subnet: str,
    search_base: str,
    attributes: List[str] = DEFAULT_ATTRS,
    operation_timeout: int = DEFAULT_OPERATION_TIMEOUT,
) -> Dict[str, str]:
    """
    Queries Active Directory for information about a specific subnet.

    Args:
        logger: A configured logger instance.
        ldap_link: An active and bound ldap3.Connection object.
        subnet: The name of the subnet to search for (e.g., "192.168.1.0/24").
        search_base: The LDAP search base.
        attributes: A list of attributes to retrieve.

    Returns:
        A dictionary containing the subnet's information if found,
        otherwise an empty dictionary.
    """
    if not ldap_link or not ldap_link.bound:
        logger.warning("AD connection is not available or not bound. Skipping search.")
        return {}

    safe_subnet = escape_filter_chars(subnet)
    search_filter = f'(&(objectClass=subnet)(name={safe_subnet}))'

    try:
        ldap_link.search(
            search_base,
            search_filter,
            attributes=attributes,
            time_limit=operation_timeout,
        )

        if ldap_link.entries:
            data = ldap_link.entries[0]
            logger.info(f"AD - Found result for subnet: {subnet}")

            site_container = "Unknown"
            if data.siteObject:
                dn_parts = str(data.siteObject).split(',')
                for part in dn_parts:
                    if part.strip().upper().startswith("CN="):
                        site_container = part.strip().split('=', 1)[1]
                        break

            return {
                "AD Name": str(data.name or ''),
                "AD Site": site_container,
                "AD Location": str(data.location or ''),
                "AD Description": str(data.description or ''),
                "AD Created": str(data.whenCreated or ''),
                "AD Changed": str(data.whenChanged or ''),
            }
        else:
            logger.info(f"AD - No results found for subnet: {subnet}")

    except LDAPException as e:
        if isinstance(e, RETRYABLE_EXCEPTIONS):
            raise
        logger.error(f"An LDAP error occurred during search: {e}")

    return {}
