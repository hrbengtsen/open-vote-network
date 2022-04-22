use concordium_std::*;
use k256::ProjectivePoint;

pub mod crypto;

#[derive(Debug, Serialize, Reject)]
enum CryptoError {
    // Failed parsing the parameter
    #[from(ParseError)]
    ParseParams,
    //dlog error
    DlogErr,
}

#[derive(Serialize)]
enum CryptoState {
    ///Crypto state is active
    Active,
    Inactive,
}

/// Struct
#[derive(Serialize, SchemaType, PartialEq, Default, Clone)]
pub struct SchnorrProof {
    r: Vec<u8>,
    g_w: Vec<u8>,
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
    //Always succed in init
    Ok(CryptoState::Active)
}

#[receive(contract = "crypto", name = "verify_dlog", parameter = "Dlogstuff")]
fn verify_dlog<A: HasActions>(
    ctx: &impl HasReceiveContext,
    _state: &mut CryptoState,
) -> Result<A, CryptoError> {
    let dlogstuff: (Vec<u8>, SchnorrProof) = ctx.parameter_cursor().get()?;

    //ensure proof is valid
    ensure!(
        crypto::verify_dl_zkp(crypto::convert_vec_to_point(dlogstuff.0), dlogstuff.1),
        CryptoError::DlogErr
    );

    // accept if proved is verified
    Ok(A::accept())
}

#[receive(
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
        CryptoError::DlogErr
    );

    // accept if proved is verified
    Ok(A::accept())
}
