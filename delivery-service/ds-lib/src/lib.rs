//! # OpenMLS Delivery Service Library
//!
//! This library provides structs and necessary implementations to interact with
//! the OpenMLS DS.
//!
//! Clients are represented by the `ClientInfo` struct.

use openmls::prelude::*;
use tls_codec::{
    TlsByteSliceU16, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8, TlsDeserialize, TlsSerialize,
    TlsSize, TlsVecU32,
};

/// Information about a client.
/// To register a new client create a new `ClientInfo` and send it to
/// `/clients/register`.
#[derive(Debug, Default, Clone)]
pub struct ClientInfo {
    pub client_name: String,
    pub key_packages: ClientKeyPackages,
    pub id: Vec<u8>,
    pub msgs: Vec<MlsMessageIn>,
    pub welcome_queue: Vec<Welcome>,
}

/// The DS returns a list of key packages for a client as `ClientKeyPackages`.
/// This is a tuple struct holding a vector of `(Vec<u8>, KeyPackage)` tuples,
/// where the first value is the key package hash (output of `KeyPackage::hash`)
/// and the second value is the corresponding key package.
#[derive(Debug, Default, Clone, PartialEq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ClientKeyPackages(pub TlsVecU32<(TlsByteVecU8, KeyPackage)>);

impl ClientInfo {
    /// Create a new `ClientInfo` struct for a given client name and vector of
    /// key packages with corresponding hashes.
    pub fn new(client_name: String, mut key_packages: Vec<(Vec<u8>, KeyPackage)>) -> Self {
        Self {
            client_name,
            id: key_packages[0].1.credential().identity().to_vec(),
            key_packages: ClientKeyPackages(
                key_packages
                    .drain(..)
                    .map(|(e1, e2)| (e1.into(), e2))
                    .collect::<Vec<(TlsByteVecU8, KeyPackage)>>()
                    .into(),
            ),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
        }
    }

    /// The identity of a client is defined as the identity of the first key
    /// package right now.
    pub fn id(&self) -> &[u8] {
        self.id.as_slice()
    }
}

/// The DS returns a list of messages on `/recv/{name}`, which is a
/// `Vec<Message>`. A `Message` is either an `MLSMessage` or a `Welcome` message
/// (see OpenMLS) for details.
#[derive(Debug)]
pub enum Message {
    /// An `MLSMessage` is either an OpenMLS `MlsCiphertext` or `MlsPlaintext`.
    MlsMessage(MlsMessageIn),

    /// An OpenMLS `Welcome` message.
    Welcome(Welcome),
}

/// Enum defining encodings for the different message types/
#[derive(Debug, Clone, Copy, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum MessageType {
    /// An MlsMessage message.
    MlsMessage = 0,

    /// A Welcome message.
    Welcome = 2,
}

/// An core group message.
/// This is an `MLSMessage` plus the list of recipients as a vector of client
/// names.
#[derive(Debug)]
pub struct GroupMessage {
    pub msg: MlsMessageIn,
    pub recipients: TlsVecU32<TlsByteVecU32>,
}

impl GroupMessage {
    /// Create a new `GroupMessage` taking an `MlsMessageIn` and slice of
    /// recipient names.
    pub fn new(msg: MlsMessageIn, recipients: &[Vec<u8>]) -> Self {
        Self {
            msg,
            recipients: recipients
                .iter()
                .map(|r| r.clone().into())
                .collect::<Vec<TlsByteVecU32>>()
                .into(),
        }
    }

    pub fn group_id(&self) -> &GroupId {
        self.msg.group_id()
    }

    pub fn epoch(&self) -> GroupEpoch {
        self.msg.epoch()
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        self.msg.is_handshake_message()
    }
}

impl tls_codec::Size for ClientInfo {
    fn tls_serialized_len(&self) -> usize {
        TlsByteSliceU16(self.client_name.as_bytes()).tls_serialized_len()
            + self.key_packages.tls_serialized_len()
    }
}

impl tls_codec::Serialize for ClientInfo {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = TlsByteSliceU16(self.client_name.as_bytes()).tls_serialize(writer)?;
        self.key_packages.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for ClientInfo {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let client_name =
            String::from_utf8_lossy(TlsByteVecU16::tls_deserialize(bytes)?.as_slice()).into();
        let mut key_packages: Vec<(TlsByteVecU8, KeyPackage)> =
            TlsVecU32::<(TlsByteVecU8, KeyPackage)>::tls_deserialize(bytes)?.into();
        let key_packages = key_packages
            .drain(..)
            .map(|(e1, e2)| (e1.into(), e2))
            .collect();
        Ok(Self::new(client_name, key_packages))
    }
}

impl tls_codec::Size for Message {
    fn tls_serialized_len(&self) -> usize {
        MessageType::Welcome.tls_serialized_len()
            + match self {
                Message::MlsMessage(mm) => mm.tls_serialized_len(),
                Message::Welcome(w) => w.tls_serialized_len(),
            }
    }
}

impl tls_codec::Serialize for Message {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written;
        match self {
            Message::MlsMessage(m) => {
                written = MessageType::MlsMessage.tls_serialize(writer)?;
                m.tls_serialize(writer)
            }
            Message::Welcome(m) => {
                written = MessageType::Welcome.tls_serialize(writer)?;
                m.tls_serialize(writer)
            }
        }
        .map(|l| l + written)
    }
}

impl tls_codec::Deserialize for Message {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let msg_type = MessageType::tls_deserialize(bytes)?;
        Ok(match msg_type {
            MessageType::MlsMessage => Message::MlsMessage(MlsMessageIn::tls_deserialize(bytes)?),
            MessageType::Welcome => Message::Welcome(Welcome::tls_deserialize(bytes)?),
        })
    }
}

impl tls_codec::Size for GroupMessage {
    fn tls_serialized_len(&self) -> usize {
        self.msg.tls_serialized_len() + self.recipients.tls_serialized_len()
    }
}

impl tls_codec::Serialize for GroupMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.msg.tls_serialize(writer)?;
        self.recipients.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for GroupMessage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let msg = MlsMessageIn::tls_deserialize(bytes)?;
        let recipients = TlsVecU32::<TlsByteVecU32>::tls_deserialize(bytes)?;
        Ok(Self { msg, recipients })
    }
}
