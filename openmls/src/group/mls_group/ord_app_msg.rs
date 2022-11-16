//! MLS Ordered Application Messages
//!
//! This module contains operations related to sending ordered application
//! messages.
use core_group::create_commit_params::CreateCommitParams;
use log::debug;
use tls_codec::Serialize;

use super::*;

impl MlsGroup {
    /// Creates a new ordered application message proposal + commit
    pub fn send_ord_app_msg(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        bytes: Vec<u8>,
    ) -> Result<MlsMessageOut, OrdAppMsgError> {
        self.is_operational()?;

        // Create inline add proposals from key packages
        let inline_proposals = vec![Proposal::OrdAppMsg(OrdAppMsgProposal { bytes: bytes })];

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .ok_or(OrdAppMsgError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, backend)?;
        debug!("The commit result is {:?}", create_commit_result);

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_message(create_commit_result.commit, backend)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_messages)
    }
}
