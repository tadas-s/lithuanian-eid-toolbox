import os, pathlib, re, subprocess
from flask import Flask, request, jsonify
from flask_cors import CORS
import PyKCS11
from base64 import b64encode, b64decode
from hashlib import sha256
from asn1crypto.x509 import Certificate

# Server partially implements https://elpako.lt/ software protocol for authentication.

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "https://api.elpako.lt"}})

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(pkcs11dll_filename='/usr/lib64/opensc-pkcs11.so')

def certificate_for_authentication(certificate):
    key_usage_digital_signature = False
    extended_key_usage_client_auth = False

    for ext in certificate['tbs_certificate']['extensions']:
        if ext['extn_id'].native == 'key_usage' and 'digital_signature' in ext['extn_value'].native:
            key_usage_digital_signature = True
        if ext['extn_id'].native == 'extended_key_usage' and 'client_auth' in ext['extn_value'].native:
            extended_key_usage_client_auth = True

    return key_usage_digital_signature and extended_key_usage_client_auth

def get_pin(card_name):
    proc = subprocess.Popen(['pinentry'], text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    proc.stdin.write("\n".join([
        "SETTIMEOUT 60",
        "SETPROMPT Asmens Tapatybės Kortelė",
        f"SETDESC Įveskite PIN kodą autentifikavimui%0AATK vardas: {card_name}",
        "SETOK Gerai",
        "SETCANCEL Atšaukti",
        "GETPIN"
    ]) + "\n")

    proc.stdin.flush()

    outs, errs = proc.communicate(timeout=65)

    try:
        pin_line = next(filter(lambda l: l.startswith('D '), outs.split("\n")))
    except StopIteration:
        return None

    match = re.match('^D (\\d{6,12})$', pin_line)

    if match:
        return match[1]

    return None

def open_session_with_pin(slot, pin):
    tries = 3
    session = None

    while tries > 0:
        try:
            print(f"Trying to open session with pin ({tries})")
            if session is not None:
                session.closeSession()

            session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
            session.login(pin)

            return session
        except PyKCS11.PyKCS11Error as e:
            tries = tries - 1

            # Only retry one specific CKR_GENERAL_ERROR
            if e.value != PyKCS11.CKR_GENERAL_ERROR:
                raise e

    return session

@app.route("/", methods=["GET"])
def main_index():
    return "<p>Parašo serveris veikia.</p>"

@app.route("/Handshake/Browser", methods=["GET"])
def handshake_browser():
    # This supposed to return current user name, but it's only really
    # relevant to the proprietary software which runs as root + as current user.
    # So in our case - just return a dummy name.
    return "jonas"

@app.route("/Signing/GetVersion", methods=["GET"])
def signing_get_version():
    return "3.3.8"

# GET /Signing/SelectCertificate?childName=jonas&sessionId=null&store=usb2&purpose=authentication&withLog=false
@app.route("/Signing/SelectCertificate", methods=["GET"])
def signing_select_certificate():
    if request.args.get('purpose') != 'authentication':
        return jsonify({
            "exception": "Galima tik autentifikacija.",
            "errorCode": "only_authentication"
        })

    slots = pkcs11.getSlotList(tokenPresent=True)

    for slot in slots:
        session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        certificates = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])

        if len(certificates) == 0:
            session.closeSession()
            continue

        der = bytes(certificates[0].to_dict()['CKA_VALUE'])

        session.closeSession()

        certificate = Certificate.load(der)

        if certificate_for_authentication(certificate):
            return jsonify({
                "certificate": b64encode(der).decode('utf-8'),
                "name": certificate['tbs_certificate']['subject'].native['common_name'],
                "issuer": certificate['tbs_certificate']['issuer'].native['organization_name'],
                "validTo": certificate['tbs_certificate']['validity']['not_after'].native.date().isoformat()
            })

    return jsonify({
        "exception": "Nerastas tinkamas autentifikacijos sertifikatas. Patikrinkite ar kortelė skaitytuve ir paruošta darbui.",
        "errorCode": "no_certificate"
    })

@app.route("/Signing/Sign", methods=["POST"])
def signing_sign():
    request_params = request.get_json()
    certificate_to_use = b64decode(request_params['certificate'])
    data_to_sign = sha256(b64decode(request_params['dtbs'])).digest()
    slot_to_use = None
    session = None
    der = None

    slots = pkcs11.getSlotList(tokenPresent=True)

    for slot in slots:
        session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        certificates = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])

        if len(certificates) == 0:
            session.closeSession()
            continue

        der = bytes(certificates[0].to_dict()['CKA_VALUE'])

        session.closeSession()

        if der == certificate_to_use:
            slot_to_use = slot
            break

    if slot_to_use is None:
        return jsonify({
            "exception": "Nerastas tinkamas sertifikatas",
            "errorCode": "bad_cert"
        })

    certificate = Certificate.load(der)
    card_name = certificate['tbs_certificate']['subject'].native['common_name']

    pin = get_pin(card_name)

    if not pin:
        return jsonify({
            "exception": "Neįvestas/neteisingas PIN",
            "errorCode": "bad_pin"
        })

    try:
        session = open_session_with_pin(slot_to_use, pin)
    except PyKCS11.PyKCS11Error as e:
        exception_description = f"Klaida: {e}"

        if e.value == PyKCS11.CKR_PIN_INCORRECT:
            exception_description = "Neteisingas PIN"

        return jsonify({
            "exception": exception_description,
            "errorCode": "bad_pin"
        })

    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)
    private_key = session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
    ])[0]

    signature = bytes(session.sign(private_key, data_to_sign, mechanism))

    session.logout()
    session.closeSession()

    return jsonify({
        "result": b64encode(signature).decode('utf-8')
    })

def run():
    from werkzeug.serving import run_simple

    ssl_context = (
        os.path.join(pathlib.Path(__file__).parent, 'ssl', 'cert.pem'),
        os.path.join(pathlib.Path(__file__).parent, 'ssl', 'key.pem'),
    )

    run_simple(
        hostname='127.0.0.1',
        port=38888,
        application=app,
        ssl_context=ssl_context,
        threaded=False,
        processes=1
    )
