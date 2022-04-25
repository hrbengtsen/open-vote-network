use concordium_std::*;

pub mod crypto;

type VotingContractAddress = ContractAddress;

#[derive(Debug, Serialize, Reject)]
enum CryptoError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    // Error in Schnorr proof
    SchnorrErr,
    // Only the owner of the voting contract can connect to voting contract
    OnlyOwnerCanConnect,
    AlreadyConnected,
    // Sender cannot be contract
    ContractSender,
}

#[contract_state(contract = "crypto")]
#[derive(Serialize, SchemaType)]
pub struct CryptoState {
    voting_contract_address: Vec<u8>
}

/// Struct
#[derive(Serialize, SchemaType, PartialEq, Default, Clone)]
pub struct SchnorrProof {
    r: Vec<u8>,
    g_w: Vec<u8>,
}

#[derive(Serialize, SchemaType)]
struct RegisterMessage {
    voting_key: Vec<u8>,          // g^x
    voting_key_zkp: SchnorrProof, // zkp for x
}

#[derive(Serialize, SchemaType, Default, PartialEq, Clone)]
pub struct OneInTwoZKP {
    r1: Vec<u8>,
    r2: Vec<u8>,
    d1: Vec<u8>,
    d2: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
    a1: Vec<u8>,
    b1: Vec<u8>,
    a2: Vec<u8>,
    b2: Vec<u8>,
}

#[init(contract = "crypto")]
fn crypto_init(_ctx: &impl HasInitContext) -> InitResult<CryptoState> {
    Ok(CryptoState {
        voting_contract_address: Default::default()
    })
}

#[receive(contract = "crypto", name = "set_voting_contract", parameter = "VotingContractAddress")]
fn set_voting_contract<A: HasActions>(
    ctx: &impl HasReceiveContext,
    state: &mut CryptoState
) -> Result<A, CryptoError> {
    let owner = ctx.owner();

    // Get sender address and bail if its another smart contract
    let sender_address = match ctx.sender() {
        Address::Contract(_) => bail!(CryptoError::ContractSender),
        Address::Account(account_address) => account_address,
    };

    ensure!(owner == sender_address, CryptoError::OnlyOwnerCanConnect);

    let voting_contract_address: VotingContractAddress = ctx.parameter_cursor().get()?;

    ensure!(state.voting_contract_address == Vec::new(), CryptoError::AlreadyConnected);

    state.voting_contract_address = to_bytes(&voting_contract_address);

    Ok(A::accept())
}

#[receive(contract = "crypto", name = "verify_schnorr", parameter = "RegisterInfo")]
fn verify_schnorr<A: HasActions>(
    ctx: &impl HasReceiveContext,
    _state: &mut CryptoState,
) -> Result<A, CryptoError> {
    let register_info: (RegisterMessage, AccountAddress) = ctx.parameter_cursor().get()?;

    // Ensure proof is valid
    ensure!(
        crypto::verify_dl_zkp(crypto::convert_vec_to_point(register_info.0.voting_key), register_info.0.voting_key_zkp),
        CryptoError::SchnorrErr
    );

    // accept if proved is verified
    Ok(A::accept())
}

/*#[receive(
    contract = "crypto",
    name = "verify_one_of_two_zkp",
    parameter = "OneInTwo"
)]
fn verify_one_of_two_zkp<A: HasActions>(
    ctx: &impl HasReceiveContext,
    _state: &mut CryptoState,
) -> Result<A, CryptoError> {
    let one_in_two: (OneInTwoZKP, Vec<u8>) = ctx.parameter_cursor().get()?;

    //ensure proof is valid
    ensure!(
        crypto::verify_one_out_of_two_zkp(one_in_two.0, crypto::convert_vec_to_point(one_in_two.1)),
        CryptoError::SchnorrErr
    );

    // accept if proved is verified
    Ok(A::accept())
}*/
