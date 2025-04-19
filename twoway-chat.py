import argparse
import socket
import sys
import threading
from os import urandom
from classes import *
from pygost.gost34112012512 import new as gost3411_256
from pygost.gost3410 import sign, prv_unmarshal, public_key, CURVES, pub_marshal
from pygost.utils import hexenc
import pyderasn
import base64
from pygost.gost3410 import sign, verify
from pyderasn import Any, OctetString, Sequence, SetOf, IA5String, ObjectIdentifier
import os
import struct
from pygost.gost3412 import GOST3412Kuznechik
from pygost.gost3410_vko import kek_34102012256
from pygost.kdf import kdf_gostr3411_2012_256
from pygost.gost28147 import cfb_encrypt, cfb_decrypt

curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
BLOCK_SIZE = 16

def unpad(data):
    pad_index = data.rfind(b'\x80')
    if pad_index == -1:
        return data
    return data[:pad_index]


def pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + b'\x80' + b'\x00' * (pad_len - 1)

def chunk(data, size):
    return [data[i:i+size] for i in range(0, len(data), size)]

def receive_messages(conn, sig_prv_raw, sig_cert_der,kem_cer,recipient_prv_raw,prv_raw, sender_pub,recipient_pub,sender_pub_cer_key):
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

            content_info_enveloped = ContentInfoEnveloped().decode(der_data)
            enveloped_data = content_info_enveloped[0]["content"]

            recipient_info = enveloped_data["recipientInfos"]
            encrypted_key = recipient_info["encryptedKey"]

            ciphertext1 = encrypted_key._value

            sender_pub = public_key(curve, prv_unmarshal(prv_raw))
            ukm_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08"
            seed = b"\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
            ukm = int.from_bytes(ukm_bytes, "little")
            shared_secret = kek_34102012256(curve,prv_unmarshal(recipient_prv_raw),sender_pub,ukm)
            key = kdf_gostr3411_2012_256(shared_secret, ukm_bytes, seed)
            session_key = cfb_decrypt(key, ciphertext1, iv=b"\x00" * 8)

            cipher = GOST3412Kuznechik(session_key)
            encrypted_content = enveloped_data["encryptedContent"]._value

            blocks = [encrypted_content[i:i + BLOCK_SIZE] for i in range(0, len(encrypted_content), BLOCK_SIZE)]
            decrypted = b"".join(cipher.decrypt(block) for block in blocks)
            unpadded = unpad(decrypted)

            content_info_signed = ContentInfo().decode(unpadded)
            signed_data = content_info_signed[0]["content"]

            encap = signed_data["encapContentInfo"]
            signed_content = encap["eContent"]._value

            signer_info = signed_data["signerInfos"][0]
            signature = signer_info["signature"]._value

            dgst = gost3411_256(signed_content).digest()[::-1]

            print(f"\n[СООБЩЕНИЕ ОТ СОБЕСЕДНИКА] {signed_content.decode('utf-8')}")


curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]

def send_messages(sock, sig_prv_raw, sig_cert_der,kem_cer,prv_raw, recipient_prv_raw, sender_pub,recipient_pub):
    sig_prv = prv_unmarshal(sig_prv_raw)

    while True:
            text = input()
            if text.lower() == "exit":
                break

            message_bytes = text.encode("utf-8")
            dgst = gost3411_256(message_bytes).digest()[::-1]
            signature = sign(curve, sig_prv, dgst)

            digest_algorithm = AlgorithmIdentifier([("algorithm", ObjectIdentifier("1.2.643.7.1.1.2.3"))])
            signature_algorithm = AlgorithmIdentifier([("algorithm", ObjectIdentifier("1.2.643.7.1.1.3.3")),])

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
                ("serialNumber", CertificateSerialNumber(12345678)),
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
                ("certificates", Any(sig_cert_der)),
                ("signerInfos", SignerInfos([signer_info])),
            ])

            content_info = ContentInfo([
                ("contentType", ObjectIdentifier("1.2.840.113549.1.7.2")),
                ("content", signed_data),
            ])
            der_signed = content_info.encode()

            session_key = urandom(32)
            ukm_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08"
            ukm = int.from_bytes(ukm_bytes, "little")
            seed = b"\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
            shared_secret = kek_34102012256(curve, prv_unmarshal(prv_raw), public_key(curve, prv_unmarshal(recipient_prv_raw)), ukm)
            key = kdf_gostr3411_2012_256(shared_secret, ukm_bytes, seed)
            iv = urandom(8)
            ciphertext = cfb_encrypt(key, session_key, iv=b"\x00" * 8)

            cipher = GOST3412Kuznechik(session_key)
            padded_signed = pad(der_signed)
            encrypted_content = b"".join(cipher.encrypt(block) for block in chunk(padded_signed, BLOCK_SIZE))


            sender_prv = prv_unmarshal(prv_raw)
            recipient_prv = prv_unmarshal(recipient_prv_raw)


            recipient_info = RecipientInfo([
                ("encryptedKey", OctetString(ciphertext)),
            ])
            enveloped_data = EnvelopedData([
                ("version", CMSVersion(0)),
                ("recipientInfos", recipient_info),
                ("contentType", ObjectIdentifier("1.2.840.113549.1.7.2")),
                ("contentEncryptionAlgorithm", AlgorithmIdentifier([("algorithm", ObjectIdentifier("1.2.643.7.1.1.5.1")),])),
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
    conn.sendall(file_size.to_bytes(4, 'big'))
    conn.sendall(file_data)

def receive_file_data(conn):
    file_size = int.from_bytes(conn.recv(4), 'big')
    file_data = b''

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
        remote_key = receive_file_data(s)
        remote_kem_cer = receive_file_data(s)
        remote_kem_key = receive_file_data(s)
        remote_trusted_sig = receive_file_data(s)
        remote_trusted_kem = receive_file_data(s)

        send_file_data(s, sig_cer)
        send_file_data(s, sig_key)
        send_file_data(s, kem_cer)
        send_file_data(s, kem_key)
        send_file_data(s, trusted_sig)
        send_file_data(s, trusted_kem)

        if verify_trusted_data(remote_cert, remote_kem_cer, remote_trusted_sig, remote_trusted_kem):
            print("Сертификаты подтверждены.")
            threading.Thread(target=receive_messages, args=(s,sig_key, sig_cer,kem_cer,kem_key, remote_kem_key,extract_subject_public_key_info_hash(remote_kem_cer),extract_subject_public_key_info_hash(kem_cer),extract_pub(remote_cert)), daemon=True).start()
            send_messages(s, sig_key, sig_cer,kem_cer,kem_key, remote_kem_key,extract_subject_public_key_info_hash(kem_cer),extract_subject_public_key_info_hash(remote_kem_cer))
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
        send_file_data(conn, sig_key)
        send_file_data(conn, kem_cer)
        send_file_data(conn, kem_key)
        send_file_data(conn, trusted_sig)
        send_file_data(conn, trusted_kem)

        remote_cert = receive_file_data(conn)
        remote_key = receive_file_data(conn)
        remote_kem_cer = receive_file_data(conn)
        remote_kem_key = receive_file_data(conn)
        remote_trusted_sig = receive_file_data(conn)
        remote_trusted_kem = receive_file_data(conn)

        if verify_trusted_data(remote_cert, remote_kem_cer, remote_trusted_sig, remote_trusted_kem):
            print("Сертификаты подтверждены.")
            threading.Thread(target=receive_messages, args=(conn,sig_key, sig_cer,kem_cer,kem_key, remote_kem_key,extract_subject_public_key_info_hash(kem_cer),extract_subject_public_key_info_hash(remote_kem_cer),extract_subject_public_key_info_hash(remote_cert)), daemon=True).start()
            send_messages(conn,sig_key, sig_cer,kem_cer,kem_key, remote_kem_key,extract_subject_public_key_info_hash(kem_cer),extract_subject_public_key_info_hash(remote_kem_cer))
        else:
            print("Ошибка в сертификатах удалённого собеседника.")
            sys.exit(1)

def extract_pub(cert_base64):
    cert, _ = Certificate().decode(cert_base64)

    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"]._value[1]
    return spki

def extract_subject_public_key_info_hash(cert_base64):
    cert, _ = Certificate().decode(cert_base64)

    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    spki_der = spki.encode()

    hash_obj = gost3411_256()
    hash_obj.update(spki_der)
    stribog256_hash = hash_obj.digest().hex().upper()
    return stribog256_hash

def verify_trusted_data(cert_base64, kem_cer_base64, trusted_sig, trusted_kem):
    cert_hash = extract_subject_public_key_info_hash(cert_base64).upper()
    key_hash = extract_subject_public_key_info_hash(kem_cer_base64).upper()
    trusted_sig_hash = trusted_sig.decode().strip().upper()
    trusted_kem_hash = trusted_kem.decode().strip().upper()

    if cert_hash == trusted_sig_hash and key_hash == trusted_kem_hash:
        return True
    else:
        print("Хэши сертификатов и ключей не совпадают.")
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
    with open(args.trusted_sig, "rb") as f:
        trusted_sig = f.read()
    with open(args.trusted_kem, "rb") as f:
        trusted_kem = f.read()

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
