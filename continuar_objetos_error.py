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
START_AFTER = "QUI_DMZ_TELEFONIA"

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
OBJECTS_URL = "https://api.strata.paloaltonetworks.com/config/objects/v1"

token = None


def get_token():
    payload = {
        "grant_type": "client_credentials",
        "scope": f"tsg_id:{TSG_ID}"
    }

    r = requests.post(
        AUTH_URL,
        data=payload,
        auth=(CLIENT_ID, CLIENT_SECRET),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=60
    )

    print("Auth status:", r.status_code)

    if r.status_code not in [200, 201]:
        print(r.text)
        raise SystemExit("Error obteniendo token")

    return r.json()["access_token"]


def post_with_retry(url, payload, max_retries=7):
    global token

    for intento in range(1, max_retries + 1):
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            r = requests.post(url, json=payload, headers=headers, timeout=120)

            if r.status_code == 401:
                print("[TOKEN] Token vencido. Renovando...")
                token = get_token()
                continue

            time.sleep(0.5)
            return r

        except RequestException as e:
            print(f"[RED] Intento {intento}/{max_retries}: {e}")
            time.sleep(15)

    raise SystemExit("No se pudo continuar por error de red.")


def parse_addresses(root):
    addresses = []

    for entry in root.findall(".//vsys/entry/address/entry"):
        name = entry.attrib.get("name")

        payload = {
            "name": name,
            "snippet": SNIPPET
        }

        ip_netmask = entry.findtext("ip-netmask")
        ip_range = entry.findtext("ip-range")
        fqdn = entry.findtext("fqdn")

        if ip_netmask:
            payload["ip_netmask"] = ip_netmask
        elif ip_range:
            payload["ip_range"] = ip_range
        elif fqdn:
            payload["fqdn"] = fqdn
        else:
            continue

        addresses.append(payload)

    return addresses


def main():
    global token

    open("errores_resume_addresses.txt", "w", encoding="utf-8").close()

    print("Leyendo XML...")
    tree = ET.parse(XML_FILE)
    root = tree.getroot()

    all_addresses = parse_addresses(root)
    print(f"Address Objects totales en XML: {len(all_addresses)}")

    start_index = None

    for i, address in enumerate(all_addresses):
        if address["name"] == START_AFTER:
            start_index = i + 1
            break

    if start_index is None:
        raise SystemExit(f"No encontré el objeto START_AFTER: {START_AFTER}")

    pending_addresses = all_addresses[start_index:]

    print(f"Último objeto ya migrado: {START_AFTER}")
    print(f"Empezando desde índice: {start_index}")
    print(f"Objetos pendientes por migrar: {len(pending_addresses)}")

    token = get_token()

    creados = 0
    existentes = 0
    errores = 0

    for address in pending_addresses:
        url = f"{OBJECTS_URL}/addresses"
        r = post_with_retry(url, address)

        if r.status_code in [200, 201]:
            print(f"[OK] addresses: {address['name']}")
            creados += 1
        elif r.status_code == 409:
            print(f"[EXISTE] addresses: {address['name']}")
            existentes += 1
        else:
            print(f"[ERROR] addresses: {address['name']}")
            print("Status:", r.status_code)
            print(r.text)
            errores += 1

            with open("errores_resume_addresses.txt", "a", encoding="utf-8") as f:
                f.write(f"\n===== {address['name']} =====\n")
                f.write(f"STATUS: {r.status_code}\n")
                f.write(r.text)
                f.write("\n")

    print("\nResumen:")
    print(f"Creados: {creados}")
    print(f"Ya existentes: {existentes}")
    print(f"Errores: {errores}")
    print("Errores guardados en errores_resume_addresses.txt")


if __name__ == "__main__":
    main()

