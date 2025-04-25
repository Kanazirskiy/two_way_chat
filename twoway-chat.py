import argparse
import base64
import os
import socket
import struct
import sys
import threading

from os import urandom

import pyderasn
from pyderasn import Any, OctetString, Sequence, SetOf, IA5String, ObjectIdentifier

from classes import *

from pygost.gost28147 import (
    SBOXES, block2ns, ns2block, cfb_encrypt, cfb_decrypt
)
import pygost.gost28147

from pygost.gost3410 import (
    CURVES, pub_marshal, pub_unmarshal, prv_unmarshal, public_key, sign, verify
)
from pygost.gost3410_vko import kek_34102012256
from pygost.gost34112012512 import new as gost3411_256
from pygost.gost3412 import GOST3412Kuznechik
from pygost.kdf import kdf_gostr3411_2012_256
from pygost.utils import hexenc
from pygost.wrap import kexp15, kimp15


sbox_name = "id-Gost28147-89-CryptoPro-A-ParamSet"
curve = CURVES["id-tc26-gost-3410-12-256-paramSetA"]
BLOCK_SIZE = 16

def unpad(data):
    pad_index = data.rfind(b"\x80")
    if pad_index == -1:
        return data
    return data[:pad_index]


def pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + b"\x80" + b"\x00" * (pad_len - 1)

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

            decoded_content_info = ContentInfoEnveloped().decod(der_data)
            enveloped = decoded_content_info["content"]

            recipient_info = enveloped["recipientInfos"]
            ciphertext_recv = bytes(recipient_info["encryptedKey"])

            outer_alg = recipient_info["keyEncryptionAlgorithm"]
            inner_alg = AlgorithmIdentifier().decod(bytes(outer_alg["parameters"]))

            ukm_recv = bytes(OctetString().decod(bytes(inner_alg["parameters"])))
            iv_recv = bytes(OctetString().decod(bytes(enveloped["contentEncryptionAlgorithm"]["parameters"])))
            encrypted_content_recv = bytes(enveloped["encryptedContent"])
            shared_secret_recv = kek_34102012256(
                curve,
                recipient_prv,
                sender_pub,
                int.from_bytes(ukm_recv, "little")
            )
            kek_recv = kdf_gostr3411_2012_256(shared_secret_recv, ukm_recv, b"\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10")

            session_key_recv = kimp15(
                lambda blk: ns2block(pygost.gost28147.encrypt(sbox_name, kek_recv, block2ns(blk[:8]))),
                lambda blk: ns2block(pygost.gost28147.encrypt(sbox_name, kek_recv, block2ns(blk[:8]))),
                8,
                ciphertext_recv,
                ukm_recv
            )

            decrypted = cfb_decrypt(
                session_key_recv,
                encrypted_content_recv,
                iv=iv_recv,
                sbox="id-tc26-gost-28147-param-Z"
            )
            unpadded = unpad(decrypted)

            content_info_signed = ContentInfo().decod(unpadded)
            signed_data = content_info_signed["content"]

            encap = signed_data["encapContentInfo"]
            signed_content = bytes(encap["eContent"])

            signer_info = signed_data["signerInfos"][0]
            signature = bytes(signer_info["signature"])

            dgst = gost3411_256(signed_content).digest()[::-1]
            valid = verify(curve, sender_sig_pub, dgst, signature)
            if (not valid):
                print("Подпись не корректна")
            print(f"\n[СООБЩЕНИЕ ОТ СОБЕСЕДНИКА] {signed_content.decode('utf-8')}")


def send_messages(sock, sig_prv_raw, sig_cert_der,prv_raw,recipient_pub):
    sig_prv = prv_unmarshal(sig_prv_raw)
    sender_prv = prv_unmarshal(prv_raw)
    while True:
            text = input()
            if text.lower() == "exit":
                break

            message_bytes = text.encode("utf-8")
            dgst = gost3411_256(message_bytes).digest()[::-1]
            signature = sign(curve, sig_prv, dgst)

            digest_algorithm = AlgorithmIdentifier([("algorithm", ObjectIdentifier("1.2.643.7.1.1.2.2"))])
            signature_algorithm = AlgorithmIdentifier([("algorithm", ObjectIdentifier("1.2.643.7.1.1.3.2")),])

            rdnSeq = RDNSequence()
            for oid, klass, value in (
                ("2.5.4.6", PrintableString, "RU"),
                ("2.5.4.3", PrintableString, "My Test Cert"),
            ):
                rdnSeq.append(RelativeDistinguishedName((
                    AttributeTypeAndValue([
                        ("type", AttributeType(oid)),
                        ("value", AttributeValue(klass(value))),
                    ]),
                )))

            issuer = Name(("rdnSequence", rdnSeq))
            issuer_and_serial = IssuerAndSerialNumber([
                ("issuer", issuer),
                ("serialNumber", CertificateSerialNumber(extract_serial(sig_cert_der))),
            ])

            signer_info = SignerInfo([
                ("version", CMSVersion(1)),
                ("sid", issuer_and_serial),
                ("digestAlgorithm", digest_algorithm),
                ("signatureAlgorithm", signature_algorithm),
                ("signature", OctetString(signature)),
            ])

            encap_content_info = EncapsulatedContentInfo([
                ("eContentType", ObjectIdentifier("1.2.840.113549.1.7.1")),
                ("eContent", OctetString(message_bytes)),
            ])

            signed_data = SignedData([
                ("version", CMSVersion(1)),
                ("digestAlgorithms", digest_algorithm),
                ("encapContentInfo", encap_content_info),
                ("signerInfos", SignerInfos([signer_info])),
            ])

            content_info = ContentInfo([
                ("contentType", ObjectIdentifier("1.2.840.113549.1.7.2")),
                ("content", signed_data),
            ])
            der_signed = content_info.encode()

            session_key = urandom(32)
            ukm = urandom(4)
            shared_secret = kek_34102012256(curve, sender_prv, recipient_pub, int.from_bytes(ukm, "little"))
            kek = kdf_gostr3411_2012_256(shared_secret, ukm, b"\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10")
            sbox_name = "id-Gost28147-89-CryptoPro-A-ParamSet"
            sbox = SBOXES[sbox_name]
            ciphertext = kexp15(
                lambda blk: ns2block(pygost.gost28147.encrypt(sbox_name, kek, block2ns(blk[:8]))),
                lambda blk: ns2block(pygost.gost28147.encrypt(sbox_name, kek, block2ns(blk[:8]))),
                8,
                session_key,
                ukm
            )

            iv = urandom(8)
            encrypted_content = cfb_encrypt(session_key, pad(der_signed), iv=iv, sbox="id-tc26-gost-28147-param-Z")



            ukm_param = AlgorithmIdentifier([
                ("algorithm", ObjectIdentifier("1.2.643.2.2.13.1")),
                ("parameters", Any(OctetString(ukm))),
            ])

            recipient_info = RecipientInfo([
                ("version", CMSVersion(3)),
                ("keyEncryptionAlgorithm", AlgorithmIdentifier([
                    ("algorithm", ObjectIdentifier("1.2.643.7.1.1.6.1")),
                    ("parameters", Any(ukm_param)),
                ])),
                ("encryptedKey", OctetString(ciphertext)),
            ])

            enveloped_data = EnvelopedData([
                ("version", CMSVersion(0)),
                ("recipientInfos", recipient_info),
                ("contentType", ObjectIdentifier("1.2.840.113549.1.7.1")),
                ("contentEncryptionAlgorithm", AlgorithmIdentifier([
                    ("algorithm", ObjectIdentifier("1.2.643.2.2.31.1")),
                    ("parameters", Any(OctetString(iv))),
                ])),
                ("encryptedContent", OctetString(encrypted_content)),
            ])

            content_info_enveloped = ContentInfoEnveloped([
                ("contentType", ObjectIdentifier("1.2.840.113549.1.7.3")),
                ("content", enveloped_data),
            ])

            der_enveloped = content_info_enveloped.encode()

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
            print("Сертификаты подтверждены.")
            threading.Thread(target=receive_messages, args=(s,
                                                            kem_key,
                                                            extract_pub(remote_cert),
                                                            extract_pub(remote_kem_cer)
                                                            ), daemon=True).start()
            send_messages(s,
                          sig_key,
                          sig_cer,
                          kem_key,
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
            print("Сертификаты подтверждены.")
            threading.Thread(target=receive_messages, args=(conn,
                                                            kem_key,
                                                            extract_pub(remote_cert),
                                                            extract_pub(remote_kem_cer)
                                                            ), daemon=True).start()
            send_messages(conn,
                          sig_key,
                          sig_cer,
                          kem_key,
                          extract_pub(remote_kem_cer))
        else:
            print("Ошибка в сертификатах удалённого собеседника.")
            sys.exit(1)

def extract_pub(cert):
    cert = Certificate().decod(cert)

    spk = bytes(cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"])
    if spk[0] == 0x03:
        return pub_unmarshal(spk[2:])
    else:
        return pub_unmarshal(spk)

def extract_serial(cert):
    cert = Certificate().decod(cert)

    serial = int(cert["tbsCertificate"]["serialNumber"])
    return serial


def extract_subject_public_key_info_hash(cert):
    cert = Certificate().decod(cert)

    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    spki_der = spki.encode()

    hash_obj = gost3411_256()
    hash_obj.update(spki_der)
    stribog256_hash = hash_obj.digest().hex().upper()
    return stribog256_hash

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

def main():
    parser = argparse.ArgumentParser(description="Программа для безопасного чата на двоих")
    parser.add_argument("--bind", help="IP и порт для прослушивания (респондер)", type=str)
    parser.add_argument("--connect", help="IP и порт для подключения (инициатор)", type=str)

    parser.add_argument("--sig-cer", help="Путь к сертификату для подписи", type=str)
    parser.add_argument("--sig-key", help="Путь к приватному ключу для подписи", type=str)
    parser.add_argument("--kem-cer", help="Путь к сертификату для соглашения ключей", type=str)
    parser.add_argument("--kem-key", help="Путь к приватному ключу для соглашения ключей", type=str)
    parser.add_argument("--trusted-sig", help="Доверенный хэш для сертификата подписи", type=str)
    parser.add_argument("--trusted-kem", help="Доверенный хэш для сертификата соглашения ключей", type=str)

    args = parser.parse_args()

    with open(args.sig_cer, "rb") as f:
        sig_cer = f.read()
    with open(args.sig_key, "rb") as f:
        sig_key = f.read()
    with open(args.kem_cer, "rb") as f:
        kem_cer = f.read()
    with open(args.kem_key, "rb") as f:
        kem_key = f.read()
    with open(args.trusted_sig, "r") as f:
        trusted_sig = {line.strip().upper() for line in f if line.strip()}
    with open(args.trusted_kem, "r") as f:
        trusted_kem = {line.strip().upper() for line in f if line.strip()}

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
