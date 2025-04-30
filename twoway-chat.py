import argparse
import base64
import os
import socket
import struct
import sys
import threading
from base64 import b64decode
from os import urandom

from pyderasn import Any
from pyderasn import BitString
from pyderasn import Boolean
from pyderasn import IA5String
from pyderasn import Integer
from pyderasn import OctetString
from pyderasn import PrintableString
from pyderasn import UTCTime


from pygost.asn1schemas.x509 import AlgorithmIdentifier
from pygost.asn1schemas.x509 import Certificate
from pygost.asn1schemas.x509 import CertificateSerialNumber
from pygost.asn1schemas.x509 import GostR34102012PublicKeyParameters
from pygost.asn1schemas.x509 import Name
from pygost.asn1schemas.x509 import ObjectIdentifier
from pygost.asn1schemas.x509 import SubjectPublicKeyInfo

from pygost.asn1schemas.cms import Attribute
from pygost.asn1schemas.cms import AttributeValue
from pygost.asn1schemas.cms import AttributeValues
from pygost.asn1schemas.cms import CMSVersion
from pygost.asn1schemas.cms import CertificateChoices
from pygost.asn1schemas.cms import CertificateSet
from pygost.asn1schemas.cms import ContentEncryptionAlgorithmIdentifier
from pygost.asn1schemas.cms import ContentInfo
from pygost.asn1schemas.cms import ContentType
from pygost.asn1schemas.cms import DigestAlgorithmIdentifier
from pygost.asn1schemas.cms import DigestAlgorithmIdentifiers
from pygost.asn1schemas.cms import EncapsulatedContentInfo
from pygost.asn1schemas.cms import EncryptedContent
from pygost.asn1schemas.cms import EncryptedContentInfo
from pygost.asn1schemas.cms import EncryptedKey
from pygost.asn1schemas.cms import EnvelopedData
from pygost.asn1schemas.cms import Gost341215EncryptionParameters
from pygost.asn1schemas.cms import GostR341012KEGParameters
from pygost.asn1schemas.cms import IssuerAndSerialNumber
from pygost.asn1schemas.cms import KeyAgreeRecipientIdentifier
from pygost.asn1schemas.cms import KeyAgreeRecipientInfo
from pygost.asn1schemas.cms import KeyEncryptionAlgorithmIdentifier
from pygost.asn1schemas.cms import OriginatorIdentifierOrKey
from pygost.asn1schemas.cms import OriginatorPublicKey
from pygost.asn1schemas.cms import RecipientEncryptedKey
from pygost.asn1schemas.cms import RecipientEncryptedKeys
from pygost.asn1schemas.cms import RecipientInfo
from pygost.asn1schemas.cms import RecipientInfos
from pygost.asn1schemas.cms import SignatureAlgorithmIdentifier
from pygost.asn1schemas.cms import SignatureValue
from pygost.asn1schemas.cms import SignerIdentifier
from pygost.asn1schemas.cms import SignerInfo
from pygost.asn1schemas.cms import SignerInfos
from pygost.asn1schemas.cms import SignedData
from pygost.asn1schemas.cms import UnprotectedAttributes
from pygost.asn1schemas.cms import UserKeyingMaterial

from pygost.asn1schemas.oids import id_data
from pygost.asn1schemas.oids import id_signedData
from pygost.asn1schemas.oids import id_contentType
from pygost.asn1schemas.oids import id_envelopedData
from pygost.asn1schemas.oids import id_gostr3412_2015_kuznyechik_ctracpkm
from pygost.asn1schemas.oids import id_gostr3412_2015_kuznyechik_wrap_kexp15
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256_paramSetA
from pygost.asn1schemas.oids import id_tc26_gost3410_2012_256
from pygost.asn1schemas.oids import id_tc26_gost3411_2012_256

from pygost.asn1schemas.prvkey import PrivateKey
from pygost.asn1schemas.prvkey import PrivateKeyInfo


from pygost.gost3410 import (
    CURVES, pub_marshal, pub_unmarshal, prv_unmarshal, public_key, sign, verify
)
from pygost.gost34112012256 import new as gost3411_256
from pygost.gost3410_vko import kek_34102012256
from pygost.gost3412 import GOST3412Kuznechik
from pygost.wrap import kexp15, kimp15
from pygost.gost3413 import ctr


curve = CURVES["id-tc26-gost-3410-12-256-paramSetA"]
BLOCK_SIZE = 16


def chunk(data, size):
    return [data[i:i+size] for i in range(0, len(data), size)]

def receive_messages(conn,recipient_prv_raw, sender_sig_pub,sender_pub):
    recipient_prv = prv_unmarshal(recipient_prv_raw)
    while True:
            len_bytes = conn.recv(4)
            if not len_bytes:
                print("Соединение закрыто удалённой стороной.")
                break

            msg_len = struct.unpack(">I", len_bytes)[0]
            der_data = b""
            while len(der_data) < msg_len:
                chunk = conn.recv(msg_len - len(der_data))
                if not chunk:
                    raise ValueError("Оборванное сообщение")
                der_data += chunk

            ci_recv = ContentInfo().decod(der_data)
            enveloped = EnvelopedData().decod(bytes(ci_recv["content"]))
            recipient_info = enveloped["recipientInfos"][0]["kari"]
            enc_info = enveloped["encryptedContentInfo"]

            ukm_recv = bytes(recipient_info["ukm"])
            encrypted_session_key_recv = bytes(recipient_info["recipientEncryptedKeys"][0]["encryptedKey"])

            originator_pub_bytes = recipient_info["originator"]["originatorKey"]["publicKey"]
            originator_pub = pub_unmarshal(bytes(originator_pub_bytes)[2:])

            shared_secret_recv = kek_34102012256(
                curve,
                recipient_prv,
                originator_pub,
                int.from_bytes(ukm_recv, "little")
            )
            kuz = GOST3412Kuznechik(shared_secret_recv)

            session_key_recv = kimp15(
                kuz.encrypt,
                kuz.encrypt,
                16,
                encrypted_session_key_recv,
                ukm_recv
            )
            iv_recv = None
            for attr in enveloped["unprotectedAttrs"]:
                if attr["attrType"] == ObjectIdentifier("1.2.643.7.1.999.1"):
                    iv_recv = bytes(OctetString().decod(bytes(attr["attrValues"][0])))
                    break
            assert iv_recv is not None, "IV не найден в unprotectedAttrs"

            encrypted_content_recv = bytes(enc_info["encryptedContent"])
            cipher = GOST3412Kuznechik(session_key_recv)
            signed_der = ctr(cipher.encrypt, 16, encrypted_content_recv, iv_recv)


            signed = SignedData().decod(signed_der)
            message = signed["encapContentInfo"]["eContent"]

            signer_info = signed["signerInfos"][0]
            signature = bytes(signer_info["signature"])
            dgst = gost3411_256(bytes(message)).digest()[::-1]
            cert = signed["certificates"][0]["certificate"]
            pubkey_bytes = bytes(OctetString().decod(bytes(cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"])))
            pubkey_point = pub_unmarshal(pubkey_bytes)
            valid = verify(curve, pubkey_point, dgst, signature)
            if (not valid):
                print("Подпись не корректна")
            print(f"[СООБЩЕНИЕ ОТ СОБЕСЕДНИКА] {bytes(message).decode('utf-8')}")


def send_messages(sock,sig_prv_raw, sig_cert_der,prv_raw,remote_kem_cer,sender_kem_pub,recipient_pub):
    sig_prv = prv_unmarshal(sig_prv_raw)
    sender_prv = prv_unmarshal(prv_raw)
    sender_cert = Certificate().decod(sig_cert_der)
    recepient_kem_cer = Certificate().decod(remote_kem_cer)
    while True:
            text = input()
            if text.lower() == "exit":
                break

            message_bytes = text.encode("utf-8")
            dgst = gost3411_256(message_bytes).digest()[::-1]
            signature = sign(curve, sig_prv, dgst)

            digest_algorithm = AlgorithmIdentifier([("algorithm", ObjectIdentifier("1.2.643.7.1.1.2.2"))])
            signature_algorithm = AlgorithmIdentifier([("algorithm", ObjectIdentifier("1.2.643.7.1.1.3.2")),])

            signed_data = SignedData((
                ("version", CMSVersion(1)),
                ("digestAlgorithms", DigestAlgorithmIdentifiers([
                    AlgorithmIdentifier((
                        ("algorithm", id_tc26_gost3411_2012_256),
                    )),
                ])),
                ("encapContentInfo", EncapsulatedContentInfo((
                    ("eContentType", ContentType(id_data)),
                    ("eContent", OctetString(message_bytes)),
                ))),
                ("certificates", CertificateSet([
                CertificateChoices(("certificate", sender_cert))
                ])),
                ("signerInfos", SignerInfos([
                    SignerInfo((
                        ("version", CMSVersion(1)),
                        ("sid", SignerIdentifier(
                            ("issuerAndSerialNumber", IssuerAndSerialNumber((
                                ("issuer", sender_cert["tbsCertificate"]["issuer"]),
                                ("serialNumber", sender_cert["tbsCertificate"]["serialNumber"]),
                        ))))),
                        ("digestAlgorithm", DigestAlgorithmIdentifier((
                            ("algorithm", id_tc26_gost3411_2012_256),
                        ))),
                        ("signatureAlgorithm", SignatureAlgorithmIdentifier((
                            ("algorithm", id_tc26_gost3410_2012_256),
                        ))),
                        ("signature", SignatureValue(OctetString(signature))),
                    ))
                ]))
            ))
            der_signed = signed_data.encode()

            session_key = urandom(32)
            ukm = urandom(8)
            shared_secret = kek_34102012256(
                curve,
                sender_prv,
                recipient_pub,
                int.from_bytes(ukm, "little")
            )

            kuz = GOST3412Kuznechik(shared_secret)
            encrypted_session_key = kexp15(
                kuz.encrypt,
                kuz.encrypt,
                16,
                session_key,
                ukm
            )
            iv = urandom(8)
            cipher = GOST3412Kuznechik(session_key)
            encrypted_content = ctr(cipher.encrypt, 16, der_signed, iv)
            originator_pubinfo = OriginatorPublicKey((
                ("algorithm", AlgorithmIdentifier((
                    ("algorithm", id_tc26_gost3410_2012_256),
                    ("parameters", Any(GostR34102012PublicKeyParameters((
                        ("publicKeyParamSet", id_tc26_gost3410_2012_256_paramSetA),
                        ("digestParamSet", id_tc26_gost3411_2012_256),
                    )))),
                ))),
                ("publicKey", BitString(OctetString(pub_marshal(sender_kem_pub)).encode())),
            ))

            recipient_info = RecipientInfo(("kari", KeyAgreeRecipientInfo((
                ("version", CMSVersion(3)),
                ("originator", OriginatorIdentifierOrKey(("originatorKey", originator_pubinfo))),
                ("ukm", UserKeyingMaterial(ukm)),
                ("keyEncryptionAlgorithm", KeyEncryptionAlgorithmIdentifier((
                    ("algorithm", id_gostr3412_2015_kuznyechik_wrap_kexp15),
                    ("parameters", Any(GostR341012KEGParameters((
                        ("algorithm", id_gostr3412_2015_kuznyechik_wrap_kexp15),
                    )))),
                ))),
                ("recipientEncryptedKeys", RecipientEncryptedKeys([
                    RecipientEncryptedKey((
                        ("rid", KeyAgreeRecipientIdentifier(
                            ("issuerAndSerialNumber", IssuerAndSerialNumber((
                                ("issuer", recepient_kem_cer["tbsCertificate"]["issuer"]),
                                ("serialNumber", recepient_kem_cer["tbsCertificate"]["serialNumber"]),
                        ))))),
                        ("encryptedKey", EncryptedKey(encrypted_session_key)),
                    ))
                ])),
            ))))

            enveloped_data = EnvelopedData((
                ("version", CMSVersion(0)),
                ("recipientInfos", RecipientInfos([recipient_info])),
                ("encryptedContentInfo", EncryptedContentInfo((
                    ("contentType", ContentType(id_signedData)),
                    ("contentEncryptionAlgorithm", ContentEncryptionAlgorithmIdentifier((
                        ("algorithm", id_gostr3412_2015_kuznyechik_ctracpkm),
                        ("parameters", Any(Gost341215EncryptionParameters((
                            ("ukm", OctetString(ukm)),
                        )))),
                    ))),
                    ("encryptedContent", EncryptedContent(encrypted_content)),
                ))),
                ("unprotectedAttrs", UnprotectedAttributes([
                    Attribute((
                        ("attrType", ContentType(ObjectIdentifier("1.2.643.7.1.999.1"))),
                        ("attrValues", AttributeValues([
                            AttributeValue(OctetString(iv))
                        ]))
                    ))
                ]))
            ))

            ci = ContentInfo((
                ("contentType", ContentType(id_envelopedData)),
                ("content", Any(enveloped_data)),
            ))

            der_enveloped = ci.encode()

            sock.sendall(struct.pack(">I", len(der_enveloped)))
            sock.sendall(der_enveloped)



def send_file_data(conn, file_data):
    file_size = len(file_data)
    conn.sendall(file_size.to_bytes(4, "big"))
    conn.sendall(file_data)

def receive_file_data(conn):
    file_size = int.from_bytes(conn.recv(4), "big")
    file_data = b""

    while len(file_data) < file_size:
        remaining_size = file_size - len(file_data)
        chunk = conn.recv(min(remaining_size, 1024))

        if not chunk:
            raise Exception("Ошибка при получении данных")

        file_data += chunk

    return file_data

def initiate_connection(host, port, sig_cer, sig_key, kem_cer, kem_key, trusted_sig, trusted_kem):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Подключено к {host}:{port}. Введите сообщения (exit для выхода):")

        remote_cert = receive_file_data(s)
        remote_kem_cer = receive_file_data(s)


        send_file_data(s, sig_cer)
        send_file_data(s, kem_cer)

        if verify_trusted_data(remote_cert, remote_kem_cer, trusted_sig, trusted_kem):
            print("Сертификаты подтверждены.\n")
            threading.Thread(target=receive_messages, args=(s,
                                                            kem_key,
                                                            extract_pub(remote_cert),
                                                            extract_pub(remote_kem_cer)
                                                            ), daemon=True).start()
            send_messages(s,
                          sig_key,
                          sig_cer,
                          kem_key,
                          remote_kem_cer,
                          extract_pub(kem_cer),
                          extract_pub(remote_kem_cer))
        else:
            print("Ошибка в сертификатах удалённого собеседника.")
            sys.exit(1)


def listen_for_connection(host, port, sig_cer, sig_key, kem_cer, kem_key, trusted_sig, trusted_kem):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Ожидание подключения на {host}:{port}...")

        conn, addr = s.accept()
        print(f"Подключение от {addr}. Введите сообщения (exit для выхода):")

        send_file_data(conn, sig_cer)
        send_file_data(conn, kem_cer)

        remote_cert = receive_file_data(conn)
        remote_kem_cer = receive_file_data(conn)

        if verify_trusted_data(remote_cert, remote_kem_cer, trusted_sig, trusted_kem):
            print("Сертификаты подтверждены. \n")
            threading.Thread(target=receive_messages, args=(conn,
                                                            kem_key,
                                                            extract_pub(remote_cert),
                                                            extract_pub(remote_kem_cer)
                                                            ), daemon=True).start()
            send_messages(conn,
                          sig_key,
                          sig_cer,
                          kem_key,
                          remote_kem_cer,
                          extract_pub(kem_cer),
                          extract_pub(remote_kem_cer))
        else:
            print("Ошибка в сертификатах удалённого собеседника.")
            sys.exit(1)

def extract_pub(cert):
    cert = Certificate().decod(cert)

    spk = bytes(cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"])
    return pub_unmarshal(spk[2:])


def extract_subject_public_key_info_hash(cert):
    cert = Certificate().decod(cert)

    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    spki_der = spki.encode()

    hash_obj = gost3411_256()
    hash_obj.update(spki_der)
    stribog256_hash = hash_obj.digest().hex().upper()
    return stribog256_hash

def extract_private_key(cert):
    begin_marker = "-----BEGIN PRIVATE KEY-----"
    end_marker = "-----END PRIVATE KEY-----"
    cert = cert.replace(begin_marker, "").replace(end_marker, "").strip()
    decoded_cert = b64decode(cert)
    private_key_info = PrivateKeyInfo().decod(decoded_cert)
    private_key = private_key_info["privateKey"]
    return bytes(OctetString().decod(bytes(private_key)))


def verify_trusted_data(cert_path, kem_cer_path, trusted_sig, trusted_kem):
    cert_hash = extract_subject_public_key_info_hash(cert_path).upper()
    key_hash = extract_subject_public_key_info_hash(kem_cer_path).upper()

    if cert_hash in trusted_sig and key_hash in trusted_kem:
        print("[✓] Сертификаты доверенные.")
        return True
    else:
        print("[-] Хэши сертификатов не найдены в доверенных списках.")
        print(f"  Сертификат: {cert_hash}")
        print(f"  Ключ:       {key_hash}")
        return False

def unpem(pem_str):
    lines = pem_str.strip().splitlines()
    b64_body = "".join(
        line for line in lines
        if not (line.startswith("-----BEGIN") or line.startswith("-----END"))
    )
    return b64decode(b64_body)

def main():
    parser = argparse.ArgumentParser(description="Программа для безопасного чата на двоих")
    parser.add_argument("--bind", help="IP и порт для прослушивания (респондер)", type=str)
    parser.add_argument("--connect", help="IP и порт для подключения (инициатор)", type=str)

    parser.add_argument("--sig-cer", help="Путь к сертификату для подписи", type=str)
    parser.add_argument("--sig-key", help="Путь к приватному ключу для подписи", type=str)
    parser.add_argument("--kem-cer", help="Путь к сертификату для соглашения ключей", type=str)
    parser.add_argument("--kem-key", help="Путь к приватному ключу для соглашения ключей", type=str)
    parser.add_argument("--trusted-sig",nargs="+", help="Доверенный хэш для сертификата подписи", type=str)
    parser.add_argument("--trusted-kem",nargs="+", help="Доверенный хэш для сертификата соглашения ключей", type=str)

    args = parser.parse_args()

    with open(args.sig_cer, "r") as f:
        sig_cer = unpem(f.read())
    with open(args.sig_key, "r") as f:
        sig_key = extract_private_key(f.read())
    with open(args.kem_cer, "r") as f:
        kem_cer = unpem(f.read())
    with open(args.kem_key, "r") as f:
        kem_key = extract_private_key(f.read())
    trusted_sig = {h.upper() for h in args.trusted_sig}
    trusted_kem = {h.upper() for h in args.trusted_kem}


    if args.bind:
        host, port = args.bind.rsplit(":", 1)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        listen_for_connection(host, int(port), sig_cer, sig_key, kem_cer, kem_key, trusted_sig, trusted_kem)

    elif args.connect:
        host, port = args.connect.rsplit(":", 1)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        initiate_connection(host, int(port), sig_cer, sig_key, kem_cer, kem_key, trusted_sig, trusted_kem)

    else:
        print("Нужно указать либо --bind, либо --connect.")
        sys.exit(1)

if __name__ == "__main__":
    main()
