import pyderasn
from pyderasn import *


class AlgorithmIdentifier(Sequence):
    schema = (
        ("algorithm", ObjectIdentifier()),
        ("parameters", Any(optional=True)),
    )


class Version(Integer):
    schema = (("v1", 0), ("v2", 1), ("v3", 2))


class CertificateSerialNumber(Integer):
    pass


class Time(Choice):
    schema = (
        ("utcTime", UTCTime()),
        ("generalTime", GeneralizedTime()),
    )

class Validity(Sequence):
    schema = (
        ("notBefore", Time()),
        ("notAfter", Time()),
    )


class SubjectPublicKeyInfo(Sequence):
    schema = (
        ("algorithm", AlgorithmIdentifier()),
        ("subjectPublicKey", BitString()),
    )

class AttributeType(ObjectIdentifier):
    pass

class AttributeValue(Any):
    pass

class AttributeTypeAndValue(Sequence):
    schema = (
        ("type", AttributeType()),
        ("value", AttributeValue()),
    )

class UniqueIdentifier(BitString):
    pass

class RelativeDistinguishedName(SetOf):
    schema = AttributeTypeAndValue()
    bounds = (1, float("+inf"))

class RDNSequence(SequenceOf):

    schema = RelativeDistinguishedName()

class Name(Choice):
    schema = (("rdnSequence", RDNSequence()),)

class Extension(Sequence):
    schema = (
        ("extnID", ObjectIdentifier()),
        ("critical", Boolean(default=False)),
        ("extnValue", OctetString()),
    )

class Extensions(SequenceOf):
    schema = Extension()
    bounds = (1, float("+inf"))

class TBSCertificate(Sequence):
    schema = (
        ("version", Version(expl=tag_ctxc(0), default="v1")),
        ("serialNumber", CertificateSerialNumber()),
        ("signature", AlgorithmIdentifier()),
        ("issuer", Name()),
        ("validity", Validity()),
        ("subject", Name()),
        ("subjectPublicKeyInfo", SubjectPublicKeyInfo()),
        ("issuerUniqueID", UniqueIdentifier(impl=tag_ctxp(1), optional=True)),
        ("subjectUniqueID", UniqueIdentifier(impl=tag_ctxp(2), optional=True)),
        ("extensions", Extensions(expl=tag_ctxc(3), optional=True)),
    )

class Certificate(Sequence):
    schema = (
        ("tbsCertificate", TBSCertificate()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signatureValue", BitString()),
    )

class IssuerAndSerialNumber(Sequence):
    schema = (
        ("issuer", Name()),
        ("serialNumber", CertificateSerialNumber()),
    )

class CMSVersion(Integer):
    schema = (("v0", 0), ("v1", 1), ("v2", 2), ("v3", 3), ("v4", 4), ("v5", 5))

class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    pass

class DigestAlgorithmIdentifiers(SetOf):
    schema = DigestAlgorithmIdentifier()
    bounds = (1, float("inf"))

class SignerIdentifier(Choice):
    schema = (
        ("issuerAndSerialNumber", IssuerAndSerialNumber()),
    )

class SignerInfo(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("sid", IssuerAndSerialNumber()),
        ("digestAlgorithm", AlgorithmIdentifier()),
        ("signatureAlgorithm", AlgorithmIdentifier()),
        ("signature", OctetString()),
    )

class SignerInfos(SetOf):
    schema = SignerInfo()
    bounds = (1, float("inf"))

class EncapsulatedContentInfo(Sequence):
    schema = (
        ("eContentType", ObjectIdentifier()),
        ("eContent", OctetString(optional=True)),
    )

class SignedData(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("digestAlgorithms", AlgorithmIdentifier()),
        ("encapContentInfo", EncapsulatedContentInfo()),
        ("signerInfos", SignerInfos()),
    )

class ContentInfo(Sequence):
    schema = (
        ("contentType", ObjectIdentifier()),
        ("content", SignedData()),
    )

class RecipientInfo(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("keyEncryptionAlgorithm", AlgorithmIdentifier()),
        ("encryptedKey", OctetString()),
    )



class EnvelopedData(Sequence):
    schema = (
        ("version", CMSVersion()),
        ("recipientInfos", RecipientInfo()),
        ("contentType", ObjectIdentifier()),
        ("contentEncryptionAlgorithm", AlgorithmIdentifier()),
        ("encryptedContent", OctetString()),
    )


class ContentInfoEnveloped(Sequence):
    schema = (
        ("contentType", ObjectIdentifier()),
        ("content", EnvelopedData()),
    )
