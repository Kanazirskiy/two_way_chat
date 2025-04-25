import argparse
import os
from datetime import datetime
from os import urandom

from pyderasn import *

from classes import *

from pygost.gost3410 import CURVES, prv_unmarshal, public_key, pub_marshal, sign
from pygost.gost34112012512 import new as gosthash
from pygost.utils import hexenc

def generate_self_signed_cert(curve, country, region, org, unit, cn, sig_cert_path, sig_key_path):
    prv_raw = urandom(32)
    prv = prv_unmarshal(prv_raw)
    pub = public_key(curve, prv)
    pub_encoded = pub_marshal(pub)

    tbs = TBSCertificate()
    tbs["serialNumber"] = CertificateSerialNumber(int.from_bytes(urandom(8), "big"))

    sign_oid = "1.2.643.7.1.1.3.2"
    param_oid = Any(OctetString(b"1.2.643.7.1.2.1.1.1").encode())

    sign_algo_id = AlgorithmIdentifier((("algorithm", ObjectIdentifier(sign_oid)),
                                        ("parameters", Any(param_oid))))
    tbs["signature"] = sign_algo_id

    rdnSeq = RDNSequence()
    for oid, klass, value in (
        ("2.5.4.6", PrintableString, country),
        ("2.5.4.8", PrintableString, region),
        ("2.5.4.7", PrintableString, "Moscow"),
        ("2.5.4.10", PrintableString, org),
        ("2.5.4.3", PrintableString, unit),
        ("1.2.840.113549.1.9.1", IA5String, cn),
    ):
        rdnSeq.append(RelativeDistinguishedName((AttributeTypeAndValue((("type", AttributeType(oid)),
                                                                      ("value", AttributeValue(klass(value))))),)))
    name = Name(("rdnSequence", rdnSeq))
    tbs["issuer"] = name
    tbs["subject"] = name

    tbs["validity"] = Validity((("notBefore", Time(("utcTime", UTCTime(datetime(2025, 1, 1))))),
                               ("notAfter", Time(("utcTime", UTCTime(datetime(2026, 1, 1)))))))

    spki = SubjectPublicKeyInfo()
    spki["algorithm"] = AlgorithmIdentifier((("algorithm", ObjectIdentifier("1.2.643.7.1.1.1.1")),
                                            ("parameters", Any(param_oid))))
    spki["subjectPublicKey"] = BitString(bytes([0x03, len(pub_encoded)]) + pub_encoded)
    tbs["subjectPublicKeyInfo"] = spki

    def sigencode(r: int, s: int) -> bytes:
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    tbs_der = tbs.encode()
    dgst = gosthash(tbs_der).digest()[::-1]
    signature = sign(curve, prv, dgst)
    signature_bytes = signature[0].to_bytes(32, "big") + signature[1].to_bytes(32, "big")

    cert = Certificate()
    cert["tbsCertificate"] = tbs
    cert["signatureAlgorithm"] = sign_algo_id
    cert["signatureValue"] = BitString(signature_bytes + b"\x00")
    cert_der = cert.encode()

    with open(sig_cert_path, "wb") as f:
        f.write(cert_der)

    with open(sig_key_path, "wb") as f:
        f.write(prv_raw)

    print(f"Сертификат подписи сохранён в {sig_cert_path}")
    print(f"Приватный ключ подписи сохранён в {sig_key_path}")
    return cert_der, prv_raw, pub_encoded

def generate_key_agreement_cert(curve, kem_cert_path, kem_key_path):
    prv_raw = urandom(32)
    prv = prv_unmarshal(prv_raw)
    pub = public_key(curve, prv)
    pub_encoded = pub_marshal(pub)

    tbs = TBSCertificate()
    tbs["serialNumber"] = CertificateSerialNumber(int.from_bytes(urandom(8), "big"))

    sign_oid = "1.2.643.7.1.1.3.2"
    param_oid = Any(OctetString(b"1.2.643.7.1.2.1.1.1").encode())

    sign_algo_id = AlgorithmIdentifier((("algorithm", ObjectIdentifier(sign_oid)),
                                        ("parameters", Any(param_oid))))
    tbs["signature"] = sign_algo_id

    rdnSeq = RDNSequence()
    for oid, klass, value in (
        ("2.5.4.6", PrintableString, "RU"),
        ("2.5.4.8", PrintableString, "Russia"),
        ("2.5.4.7", PrintableString, "Moscow"),
        ("2.5.4.10", PrintableString, "Personal"),
        ("2.5.4.3", PrintableString, "Personalproject"),
        ("1.2.840.113549.1.9.1", IA5String, "fake@gmail.com"),
    ):
        rdnSeq.append(RelativeDistinguishedName((AttributeTypeAndValue((("type", AttributeType(oid)),
                                                                      ("value", AttributeValue(klass(value))))),)))
    name = Name(("rdnSequence", rdnSeq))
    tbs["issuer"] = name
    tbs["subject"] = name

    tbs["validity"] = Validity((("notBefore", Time(("utcTime", UTCTime(datetime(2025, 1, 1))))),
                               ("notAfter", Time(("utcTime", UTCTime(datetime(2026, 1, 1)))))))

    spki = SubjectPublicKeyInfo()
    spki["algorithm"] = AlgorithmIdentifier((("algorithm", ObjectIdentifier("1.2.643.7.1.1.1.1")),
                                            ("parameters", Any(param_oid))))
    spki["subjectPublicKey"] = BitString(bytes([0x03, len(pub_encoded)]) + pub_encoded)
    tbs["subjectPublicKeyInfo"] = spki

    tbs_der = tbs.encode()
    dgst = gosthash(tbs_der).digest()[::-1]
    signature = sign(curve, prv, dgst)
    signature_bytes = signature[0].to_bytes(32, "big") + signature[1].to_bytes(32, "big")

    cert = Certificate()
    cert["tbsCertificate"] = tbs
    cert["signatureAlgorithm"] = sign_algo_id
    cert["signatureValue"] = BitString(signature_bytes + b"\x00")
    cert_der = cert.encode()

    with open(kem_cert_path, "wb") as f:
        f.write(cert_der)

    with open(kem_key_path, "wb") as f:
        f.write(prv_raw)

    print(f"Сертификат ключа обмена сохранён в {kem_cert_path}")
    print(f"Приватный ключ ключа обмена сохранён в {kem_key_path}")
    return cert_der, prv_raw, pub_encoded

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sig-cer", help="Путь к файлу сертификата подписи")
    parser.add_argument("--sig-key", help="Путь к файлу приватного ключа подписи")
    parser.add_argument("--kem-cer", help="Путь к файлу сертификата для обмена ключами")
    parser.add_argument("--kem-key", help="Путь к файлу приватного ключа для обмена ключами")

    args = parser.parse_args()

    curve = CURVES["id-tc26-gost-3410-12-256-paramSetA"]
    country = "RU"
    region = "Moscow"
    org = "Personal"
    unit = "Personalproject"
    cn = "fake@gmail.com"

    sig_cert_path = args.sig_cer or "for-signature.cer"
    sig_key_path = args.sig_key or "for-signature.prv"
    kem_cert_path = args.kem_cer or "for-key-agreement.cer"
    kem_key_path = args.kem_key or "for-key-agreement.prv"

    generate_self_signed_cert(curve, country, region, org, unit, cn, sig_cert_path, sig_key_path)

    generate_key_agreement_cert(curve, kem_cert_path, kem_key_path)

if __name__ == "__main__":
    main()
