import os
import argparse
from pygost.gost34112012512 import new as gost3411_256
from classes import *

TRUSTED_SIG_FILE = "trusted-sig.txt"
TRUSTED_KEM_FILE = "trusted-kem.txt"

def extract_subject_public_key_info_hash(cert_path):
    with open(cert_path, "rb") as f:
        der_data = f.read()
    cert = Certificate().decod(der_data)
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    spki_der = spki.encode()
    return gost3411_256(spki_der).digest().hex().upper()

def append_to_file_if_new(filename, fingerprint):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            existing = {line.strip() for line in f}
    else:
        existing = set()

    if fingerprint not in existing:
        with open(filename, "a") as f:
            f.write(fingerprint + "\n")
        print(f"[+] Добавлен в {filename}: {fingerprint}")
    else:
        print(f"[=] Уже есть в {filename}: {fingerprint}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sig-cer", help="Путь к сертификату подписи")
    parser.add_argument("--kem-cer", help="Путь к сертификату обмена ключами")
    args = parser.parse_args()

    if args.sig_cer:
        sig_fp = extract_subject_public_key_info_hash(args.sig_cer)
        print(f"Отпечаток подписи: {sig_fp}")
        append_to_file_if_new(TRUSTED_SIG_FILE, sig_fp)

    if args.kem_cer:
        kem_fp = extract_subject_public_key_info_hash(args.kem_cer)
        print(f"Отпечаток обмена ключами: {kem_fp}")
        append_to_file_if_new(TRUSTED_KEM_FILE, kem_fp)

    if not args.sig_cer and not args.kem_cer:
        print("Укажи хотя бы один из параметров --sig-cer или --kem-cer")

if __name__ == "__main__":
    main()
