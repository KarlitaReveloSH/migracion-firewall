import time
import requests
import xml.etree.ElementTree as ET

# =========================
# DATOS SCM
# =========================
CLIENT_ID = "CLOUD_API_FW@1147621434.iam.panserviceaccount.com"
CLIENT_SECRET = "c83b3af5-36cf-4d9b-9d41-d155c3dcbbf1"
TSG_ID = "1147621434"

# ==================================================
# DATOS MIGRACION
# ==================================================
XML_FILE = "QUI01-07072025.xml"
SNIPPET = "api_firewall_uio"

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
OBJECTS_URL = "https://api.strata.paloaltonetworks.com/config/objects/v1"
SECURITY_URL = "https://api.strata.paloaltonetworks.com/config/security/v1"
NETWORK_URL = "https://api.strata.paloaltonetworks.com/config/network/v1"

ERROR_LOG = "errores_migracion_scm.txt"
token = None

# ==================================================
# ACTIVAR / DESACTIVAR MIGRACIONES
# ==================================================
MIGRATE_ETHERNET_INTERFACES = True
MIGRATE_TUNNEL_INTERFACES = True
MIGRATE_LOOPBACK_INTERFACES = True
MIGRATE_ZONES = True
MIGRATE_ADDRESSES = True
MIGRATE_ADDRESS_GROUPS = True
MIGRATE_SERVICES = True
MIGRATE_SERVICE_GROUPS = True
MIGRATE_TAGS = True
MIGRATE_EXTERNAL_LISTS = True
MIGRATE_IKE_GATEWAYS = True
MIGRATE_IPSEC_TUNNELS = True
MIGRATE_SECURITY_RULES = True


# ===============================================================================================================================
# FUNCIONES BASE.- esta función es para obtener el token de autenticación y poder realizar las consultas mediante api
# =================================================================================================================================
def log_error(section, name, status, response_text):
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write("\n" + "=" * 80 + "\n")
        f.write(f"SECTION: {section}\n")
        f.write(f"NAME: {name}\n")
        f.write(f"STATUS: {status}\n")
        f.write(str(response_text))
        f.write("\n")


def get_token():
    payload = {
        "grant_type": "client_credentials",
        "scope": f"tsg_id:{TSG_ID}"
    }

    response = requests.post(
        AUTH_URL,
        data=payload,
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=120
    )

    print("Auth status:", response.status_code)

    if response.status_code not in [200, 201]:
        print(response.text)
        raise SystemExit("Error obteniendo token SCM")

    return response.json()["access_token"]


def post_with_retry(url, payload, max_retries=5):
    global token

    for attempt in range(1, max_retries + 1):
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=60
            )

            if response.status_code == 401:
                print("[TOKEN] Token expirado. Renovando token...")
                token = get_token()
                continue

            time.sleep(0.25)
            return response

        except RequestException as e:
            print(f"[RED] Error conexión intento {attempt}/{max_retries}: {e}")
            time.sleep(10)

    raise SystemExit("No se pudo conectar luego de varios intentos.")


def post_scm(section, base_url, endpoint, payload):
    url = f"{base_url}/{endpoint}"
    name = payload.get("name", "SIN_NOMBRE")

    response = post_with_retry(url, payload)

    if response.status_code in [200, 201]:
        print(f"[OK] {section}: {name}")
    elif response.status_code == 409:
        print(f"[EXISTE] {section}: {name}")
    else:
        print(f"[ERROR] {section}: {name}")
        print("Status:", response.status_code)
        print(response.text)
        log_error(section, name, response.status_code, response.text)


def get_members(entry, path):
    return [m.text for m in entry.findall(path) if m.text]


# ==================================================
# NORMALIZACION DE INTERFACES
# ==================================================
def clean_ethernet_name(name):
    return "$" + name.replace("/", "-")


def clean_tunnel_name(name):
    return "$" + name.replace(".", "-")


def clean_loopback_name(name):
    return "$" + name.replace(".", "-")


def normalize_interface_reference(name):
    if not name:
        return None

    if name.startswith("ethernet"):
        return "$" + name.replace("/", "-")

    if name.startswith("tunnel."):
        return "$" + name.replace(".", "-")

    if name.startswith("loopback."):
        return "$" + name.replace(".", "-")

    # SCM API no acepta el contenedor padre "tunnel"
    if name == "tunnel":
        return None

    return name


# ==================================================
# PARSE NETWORK
# ==================================================
def parse_ethernet_interfaces(root):
    items = []

    for entry in root.findall(".//network/interface/ethernet/entry"):
        original_name = entry.attrib.get("name")

        ip_members = [
            ip.attrib.get("name")
            for ip in entry.findall("./layer3/ip/entry")
            if ip.attrib.get("name")
        ]

        if not ip_members:
            print(f"[SKIP] Interface sin IP Layer3: {original_name}")
            continue

        payload = {
            "name": clean_ethernet_name(original_name),
            "snippet": SNIPPET,
            "layer3": {
                "ip": [{"name": ip} for ip in ip_members]
            }
        }

        items.append(payload)

    return items


def parse_tunnel_interfaces(root):
    items = []

    for entry in root.findall(".//network/interface/tunnel/units/entry"):
        original_name = entry.attrib.get("name")

        ip_members = [
            ip.attrib.get("name")
            for ip in entry.findall("./ip/entry")
            if ip.attrib.get("name")
        ]

        payload = {
            "name": clean_tunnel_name(original_name),
            "snippet": SNIPPET
        }

        if ip_members:
            payload["ip"] = [{"name": ip} for ip in ip_members]

        items.append(payload)

    return items


def parse_loopback_interfaces(root):
    items = []

    for entry in root.findall(".//network/interface/loopback/units/entry"):
        original_name = entry.attrib.get("name")

        ip_members = [
            ip.attrib.get("name")
            for ip in entry.findall("./ip/entry")
            if ip.attrib.get("name")
        ]

        payload = {
            "name": clean_loopback_name(original_name),
            "snippet": SNIPPET
        }

        if ip_members:
            payload["ip"] = [{"name": ip} for ip in ip_members]

        items.append(payload)

    return items


def parse_zones(root):
    items = []

    for entry in root.findall(".//vsys/entry/zone/entry"):
        name = entry.attrib.get("name")

        members = []

        for m in entry.findall("./network/layer3/member"):
            original_member = m.text
            normalized_member = normalize_interface_reference(original_member)

            if normalized_member:
                members.append(normalized_member)
            else:
                print(f"[SKIP] Zone {name}: miembro no soportado por API SCM -> {original_member}")

        payload = {
            "name": name,
            "snippet": SNIPPET,
            "network": {
                "layer3": members
            }
        }

        print(f"Payload zone {name}: {payload}")

        items.append(payload)

    return items


# ==================================================
# PARSE OBJECTS
# ==================================================
def parse_addresses(root):
    items = []

    for entry in root.findall(".//vsys/entry/address/entry"):
        payload = {
            "name": entry.attrib.get("name"),
            "snippet": SNIPPET
        }

        if entry.findtext("ip-netmask"):
            payload["ip_netmask"] = entry.findtext("ip-netmask")
        elif entry.findtext("ip-range"):
            payload["ip_range"] = entry.findtext("ip-range")
        elif entry.findtext("fqdn"):
            payload["fqdn"] = entry.findtext("fqdn")
        else:
            continue

        items.append(payload)

    return items


def parse_address_groups(root):
    items = []

    for entry in root.findall(".//vsys/entry/address-group/entry"):
        members = get_members(entry, "./static/member")

        if members:
            items.append({
                "name": entry.attrib.get("name"),
                "snippet": SNIPPET,
                "static": members
            })

    return items


def parse_services(root):
    items = []

    for entry in root.findall(".//vsys/entry/service/entry"):
        payload = {
            "name": entry.attrib.get("name"),
            "snippet": SNIPPET
        }

        tcp_port = entry.findtext("./protocol/tcp/port")
        udp_port = entry.findtext("./protocol/udp/port")

        if tcp_port:
            payload["protocol"] = {"tcp": {"port": tcp_port}}
        elif udp_port:
            payload["protocol"] = {"udp": {"port": udp_port}}
        else:
            continue

        items.append(payload)

    return items


def parse_service_groups(root):
    items = []

    for entry in root.findall(".//vsys/entry/service-group/entry"):
        members = get_members(entry, "./members/member")

        if members:
            items.append({
                "name": entry.attrib.get("name"),
                "snippet": SNIPPET,
                "members": members
            })

    return items


def parse_tags(root):
    items = []

    for entry in root.findall(".//vsys/entry/tag/entry"):
        payload = {
            "name": entry.attrib.get("name"),
            "snippet": SNIPPET
        }

        comments = entry.findtext("comments")
        if comments:
            payload["comments"] = comments

        # No enviamos color porque PAN-OS usa color1/color2
        # y SCM espera nombres como Red, Green, Blue, etc.

        items.append(payload)

    return items

def parse_external_lists(root):
    items = []

    for entry in root.findall(".//vsys/entry/external-list/entry"):
        name = entry.attrib.get("name")
        url = entry.findtext(".//url")

        if not url:
            print(f"[SKIP] EDL sin URL: {name}")
            continue

        if entry.find(".//type/ip") is not None:
            list_type = "ip"
        elif entry.find(".//type/domain") is not None:
            list_type = "domain"
        elif entry.find(".//type/url") is not None:
            list_type = "url"
        else:
            print(f"[SKIP] EDL tipo no detectado: {name}")
            continue

        recurring = {}

        if entry.find(".//recurring/hourly") is not None:
            recurring = {"hourly": {}}

        elif entry.find(".//recurring/daily") is not None:
            at = entry.findtext(".//recurring/daily/at")
            recurring = {"daily": {}}
            if at:
                recurring["daily"]["at"] = at

        elif entry.find(".//recurring/weekly") is not None:
            day = entry.findtext(".//recurring/weekly/day-of-week")
            at = entry.findtext(".//recurring/weekly/at")

            recurring = {"weekly": {}}
            if day:
                recurring["weekly"]["day_of_week"] = day
            if at:
                recurring["weekly"]["at"] = at

        else:
            recurring = {"hourly": {}}

        payload = {
            "name": name,
            "snippet": SNIPPET,
            "type": {
                list_type: {
                    "url": url,
                    "recurring": recurring
                }
            }
        }

        items.append(payload)

    return items


# ==================================================
# PARSE VPN
# ==================================================
def parse_ike_gateways(root):
    items = []

    for entry in root.findall(".//network/ike/gateway/entry"):
        name = entry.attrib.get("name")

        interface = entry.findtext("./local-address/interface")
        peer_ip = entry.findtext("./peer-address/ip")
        peer_fqdn = entry.findtext("./peer-address/fqdn")
        version = entry.findtext("./protocol/version", default="ikev2")
        ike_profile = entry.findtext("./protocol/ikev1/ike-crypto-profile") or entry.findtext("./protocol/ikev2/ike-crypto-profile")
        psk = entry.findtext("./authentication/pre-shared-key/key")

        payload = {
            "name": name,
            "snippet": SNIPPET,
            "protocol": {
                "version": version
            }
        }

        if ike_profile:
            payload["protocol"]["ikev2"] = {
                "ike_crypto_profile": ike_profile
            }

        if interface:
            payload["local_address"] = {
                "interface": normalize_interface_reference(interface)
            }

        if peer_ip:
            payload["peer_address"] = {
                "ip": peer_ip
            }
        elif peer_fqdn:
            payload["peer_address"] = {
                "fqdn": peer_fqdn
            }

        if psk:
            payload["authentication"] = {
                "pre_shared_key": {
                    "key": psk
                }
            }

        items.append(payload)

    return items


def parse_ipsec_tunnels(root):
    items = []

    for entry in root.findall(".//network/tunnel/ipsec/entry"):
        name = entry.attrib.get("name")

        tunnel_interface = entry.findtext("tunnel-interface")
        ipsec_profile = entry.findtext("./auto-key/ipsec-crypto-profile")

        ike_gateways = [
            gw.attrib.get("name")
            for gw in entry.findall("./auto-key/ike-gateway/entry")
            if gw.attrib.get("name")
        ]

        payload = {
            "name": name,
            "snippet": SNIPPET,
            "auto_key": {}
        }

        if tunnel_interface:
            payload["tunnel_interface"] = normalize_interface_reference(tunnel_interface)

        if ike_gateways:
            payload["auto_key"]["ike_gateway"] = [
                {"name": gw}
                for gw in ike_gateways
            ]

        if ipsec_profile:
            payload["auto_key"]["ipsec_crypto_profile"] = ipsec_profile

        proxy_ids = []

        for proxy in entry.findall("./auto-key/proxy-id/entry"):
            proxy_payload = {
                "name": proxy.attrib.get("name")
            }

            local = proxy.findtext("local")
            remote = proxy.findtext("remote")

            if local:
                proxy_payload["local"] = local
            if remote:
                proxy_payload["remote"] = remote

            if proxy.find("protocol/any") is not None:
                proxy_payload["protocol"] = {"any": {}}

            proxy_ids.append(proxy_payload)

        if proxy_ids:
            payload["auto_key"]["proxy_id"] = proxy_ids

        print(f"Payload IPsec {name}: {payload}")

        items.append(payload)

    return items


# ==================================================
# PARSE SECURITY RULES
# ==================================================
def parse_security_rules(root):
    items = []

    for entry in root.findall(".//rulebase/security/rules/entry"):
        payload = {
            "name": entry.attrib.get("name"),
            "snippet": SNIPPET,
            "from": get_members(entry, "./from/member"),
            "to": get_members(entry, "./to/member"),
            "source": get_members(entry, "./source/member"),
            "destination": get_members(entry, "./destination/member"),
            "source_user": get_members(entry, "./source-user/member"),
            "category": get_members(entry, "./category/member"),
            "application": get_members(entry, "./application/member"),
            "service": get_members(entry, "./service/member"),
            "action": entry.findtext("action", default="allow"),
            "log_start": entry.findtext("log-start", default="no") == "yes",
            "log_end": entry.findtext("log-end", default="yes") == "yes",
            "disabled": entry.findtext("disabled", default="no") == "yes"
        }

        description = entry.findtext("description")
        if description:
            payload["description"] = description

        items.append(payload)

    return items


# ==================================================
# MAIN
# ==================================================
def main():
    global token

    open(ERROR_LOG, "w", encoding="utf-8").close()

    print("Leyendo XML...")
    tree = ET.parse(XML_FILE)
    root = tree.getroot()

    #ethernet_interfaces = parse_ethernet_interfaces(root)
    #tunnel_interfaces = parse_tunnel_interfaces(root)
    #loopback_interfaces = parse_loopback_interfaces(root)
    #zones = parse_zones(root)

    #addresses = parse_addresses(root)
    address_groups = parse_address_groups(root)
    services = parse_services(root)
    service_groups = parse_service_groups(root)
    tags = parse_tags(root)
    external_lists = parse_external_lists(root)

    ike_gateways = parse_ike_gateways(root)
    ipsec_tunnels = parse_ipsec_tunnels(root)
    security_rules = parse_security_rules(root)

    #print(f"Ethernet Interfaces encontradas: {len(ethernet_interfaces)}")
    #print(f"Tunnel Interfaces encontradas: {len(tunnel_interfaces)}")
    #print(f"Loopback Interfaces encontradas: {len(loopback_interfaces)}")
    #print(f"Zones encontradas: {len(zones)}")
    #print(f"Address Objects encontrados: {len(addresses)}")
    #print(f"Address Groups encontrados: {len(address_groups)}")
    #print(f"Services encontrados: {len(services)}")
    #print(f"Service Groups encontrados: {len(service_groups)}")
    #print(f"Tags encontrados: {len(tags)}")
    #print(f"External Lists encontradas: {len(external_lists)}")
    #print(f"IKE Gateways encontrados: {len(ike_gateways)}")
    #print(f"IPsec Tunnels encontrados: {len(ipsec_tunnels)}")
    print(f"Security Rules encontradas: {len(security_rules)}")

    print("\nObteniendo token SCM...")
    token = get_token()

    #if MIGRATE_ETHERNET_INTERFACES:
     #   print("\nMigrando Ethernet Interfaces...")
      #  for item in ethernet_interfaces:
        #    post_scm("ethernet-interface", NETWORK_URL, "ethernet-interfaces", item)

    #if MIGRATE_TUNNEL_INTERFACES:
     #   print("\nMigrando Tunnel Interfaces...")
      #  for item in tunnel_interfaces:
       #     post_scm("tunnel-interface", NETWORK_URL, "tunnel-interfaces", item)

    #if MIGRATE_LOOPBACK_INTERFACES:
     #   print("\nMigrando Loopback Interfaces...")
      #  for item in loopback_interfaces:
       #     post_scm("loopback-interface", NETWORK_URL, "loopback-interfaces", item)

    #if MIGRATE_ZONES:
     #   print("\nMigrando Zones...")
      #  for item in zones:
       #     post_scm("zone", NETWORK_URL, "zones", item)

    #if MIGRATE_ADDRESSES:
     #   print("\nMigrando Address Objects...")
      #  for item in addresses:
       #     post_scm("addresses", OBJECTS_URL, "addresses", item)

    #if MIGRATE_ADDRESS_GROUPS:
     #   print("\nMigrando Address Groups...")
      #  for item in address_groups:
       #     post_scm("address-groups", OBJECTS_URL, "address-groups", item)

    #if MIGRATE_SERVICES:
     #   print("\nMigrando Services...")
      #  for item in services:
       #     post_scm("services", OBJECTS_URL, "services", item)

    #if MIGRATE_SERVICE_GROUPS:
     #   print("\nMigrando Service Groups...")
      #  for item in service_groups:
       #     post_scm("service-groups", OBJECTS_URL, "service-groups", item)

    #if MIGRATE_TAGS:
     #   print("\nMigrando Tags...")
      #  for item in tags:
       #     post_scm("tags", OBJECTS_URL, "tags", item)

    #if MIGRATE_EXTERNAL_LISTS:
     #   print("\nMigrando External Dynamic Lists...")
      #  for item in external_lists:
       #     post_scm("external-list", OBJECTS_URL, "external-dynamic-lists", item)

    #if MIGRATE_IKE_GATEWAYS:
    #    print("\nMigrando IKE Gateways...")
    #    for item in ike_gateways:
    #        post_scm("ike-gateway", NETWORK_URL, "ike-gateways", item)

    #if MIGRATE_IPSEC_TUNNELS:
     #   print("\nMigrando IPsec Tunnels...")
      #  for item in ipsec_tunnels:
       #     post_scm("ipsec-tunnel", NETWORK_URL, "ipsec-tunnels", item)

    if MIGRATE_SECURITY_RULES:
        print("\nMigrando Security Rules...")
        for item in security_rules:
            post_scm("security-rule", SECURITY_URL, "security-rules", item)

    print("\nProceso finalizado.")
    print(f"Errores guardados en: {ERROR_LOG}")


if __name__ == "__main__":
    main()
