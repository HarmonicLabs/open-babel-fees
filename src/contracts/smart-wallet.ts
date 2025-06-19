import { bool, bs, data, int, passert, pblake2b_224, pBool, PCurrencySymbol, perror, pfn, pisEmpty, plet, pmatch, PMaybe, PPubKey, PScriptContext, pserialiseData, pstruct, PTxOutRef, PubKeyHash, punIData, PUnit, pverifyEd25519, TermFn, unit } from "@harmoniclabs/plu-ts";


const SignedData = pstruct({
    SignedData: {
        allowedUtxoRef: PTxOutRef.type,
        tokenPolicy: PCurrencySymbol.type,
        tokenName: bs,
        minTokenAmount: int,
        allowedSpendLovelaceAmount: int,
        expirationTime: int
    }
});

const Rdmr = pstruct({
    Allow: {
        signedData: SignedData.type,
        signature: bs,
    },
    Withdraw: {}
});

export const contract: TermFn<[
    typeof PPubKey, // owner
    typeof PScriptContext
], PUnit> = pfn([
    PPubKey.type, // owner
    PScriptContext.type
], unit)
(( ownerPubKey, { tx, purpose, redeemer }) => passert.$(
    pmatch( purpose )
    .onSpending(({ utxoRef }) =>
        pmatch( redeemer.as( Rdmr.type ) )
        .onAllow( ({ signedData, signature }) => {

            // inlined
            const correctSignature = (
                pverifyEd25519
                .$( ownerPubKey )
                .$( pserialiseData.$( signedData.as( data ) ) )
                .$( signature )
            );

            const {
                allowedUtxoRef,
                tokenPolicy,
                tokenName,
                minTokenAmount,
                allowedSpendLovelaceAmount,
                expirationTime
            } = plet( signedData );

            // inlined
            const notexpirationTimed = punIData.$( tx.interval.to.bound.raw.fields.head ).ltEq( expirationTime );

            const { utxoRef: ownUtxoRef, resolved: ownInput } = plet( tx.inputs.filter( input => input.utxoRef.eq( utxoRef ) ).head );

            const ownAddress = plet( ownInput.address );
            const isOwnAddress = plet( ownAddress.peq );

            // inlined
            const singleOwnInput = pisEmpty.$( 
                tx.inputs.filter( input => isOwnAddress.$( input.resolved.address ) ).tail
            );

            const ownOutputs = plet( tx.outputs.filter( out => isOwnAddress.$( out.address ) ) );
            const singleOwnOutput = plet( pisEmpty.$( ownOutputs.tail ) );
            const ownOutput = plet( ownOutputs.head );

            // inlined
            const isAllowedUtxoRef = ownUtxoRef.eq( allowedUtxoRef );

            const spentLessLovelaceThanMaxAllowed = plet(
                ownInput.value.lovelaces
                .sub( ownOutput.value.lovelaces )
                .ltEq( allowedSpendLovelaceAmount )
            );

            const receivedAtLeastMinToken = plet(
                ownOutput.value.amountOf( tokenPolicy, tokenName )
                .sub( ownInput.value.amountOf( tokenPolicy, tokenName ) )
                .gtEq( minTokenAmount )
            );


            return correctSignature
            .strictAnd( notexpirationTimed )
            .strictAnd( singleOwnInput )
            .strictAnd( singleOwnOutput )
            .strictAnd( isAllowedUtxoRef )
            .strictAnd( spentLessLovelaceThanMaxAllowed )
            .strictAnd( receivedAtLeastMinToken );
        })
        .onWithdraw(() => {

            const isOwnerPkh = plet( pblake2b_224.$( ownerPubKey ).peq );

            return tx.outputs.every( out =>
                pmatch( out.address.credential )
                .onPPubKeyCredential(({ pkh }) => isOwnerPkh.$( pkh ) )
                ._( _ => pBool( false ) )
            );
        })
    )
    ._( _ => perror( bool ) )
));