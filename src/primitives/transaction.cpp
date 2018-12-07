// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

CTxOutValue::CTxOutValue()
{
    vchCommitment.resize(nCommitmentSize);
    memset(&vchCommitment[0], 0xff, nCommitmentSize);
}

CTxOutValue::CTxOutValue(CAmount nAmountIn)
{
    vchCommitment.resize(nCommitmentSize);
    SetToAmount(nAmountIn);
}

CTxOutValue::CTxOutValue(const std::vector<unsigned char>& vchValueCommitmentIn, const std::vector<unsigned char>& vchRangeproofIn)
: vchCommitment(vchValueCommitmentIn), vchRangeproof(vchRangeproofIn)
{
    assert(vchCommitment.size() == nCommitmentSize);
    assert(vchCommitment[0] == 2 || vchCommitment[0] == 3);
}

bool CTxOutValue::IsValid() const
{
    switch (vchCommitment[0])
    {
        case 0:
        {
            // Ensure all but the last sizeof(CAmount) bytes are zero
            for (size_t i = vchCommitment.size() - sizeof(CAmount); --i > 0; )
                if (vchCommitment[i])
                    return false;
            return true;
        }
        case 2:
        case 3:
            // FIXME: Additional checks?
            return true;
        default:
            return false;
    }
}

bool CTxOutValue::IsNull() const
{
    return vchCommitment[0] == 0xff;
}

bool CTxOutValue::IsAmount() const
{
    return !vchCommitment[0];
}

void CTxOutValue::SetToAmount(CAmount nAmount)
{
    assert(vchCommitment.size() > sizeof(nAmount) + 1);
    memset(&vchCommitment[0], 0, vchCommitment.size() - sizeof(nAmount));
    for (size_t i = 0; i < sizeof(nAmount); ++i)
        vchCommitment[vchCommitment.size() - (i + 1)] = ((nAmount >> (i * 8)) & 0xff);
}

CAmount CTxOutValue::GetAmount() const
{
    assert(IsAmount());
    CAmount nAmount = 0;
    for (size_t i = 0; i < sizeof(nAmount); ++i)
        nAmount |= CAmount(vchCommitment[vchCommitment.size() - (i + 1)]) << (i * 8);
    return nAmount;
}

bool operator==(const CTxOutValue& a, const CTxOutValue& b)
{
    return a.vchRangeproof == b.vchRangeproof &&
           a.vchCommitment == b.vchCommitment &&
           a.vchNonceCommitment == b.vchNonceCommitment;
}

bool operator!=(const CTxOutValue& a, const CTxOutValue& b) {
    return !(a == b);
}


std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CTxOutValue &nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue.GetAmount() / COIN, nValue.GetAmount() % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::GetWitnessHash() const
{
    if (!HasWitness()) {
        return GetHash();
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), hash(), hashFull() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash(ComputeHash()) {}

uint256 CTransaction::getHashJustWitness() const
{
    return hashJustWitness;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

void CTransaction::UpdateHash() const
{
    bool maybeBitcoinTx = true;
    for (unsigned int i = 0; i < vout.size(); i++)
        if (!vout[i].nValue.IsAmount())
            maybeBitcoinTx = false;
    if (maybeBitcoinTx)
        *const_cast<uint256*>(&hashBitcoin) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_VERSION_MASK_BITCOIN_TX);

    if (IsCoinBase()) {
        *const_cast<uint256*>(&hash) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION);
    } else {
        *const_cast<uint256*>(&hash) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    }
    *const_cast<uint256*>(&hashJustWitness) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_VERSION_MASK_ONLY_WITNESS);
    // Update full hash combining the normalized txid with the hash of the witness
    CHash256 hasher;
    hasher.Write((unsigned char*)&hash, hash.size());
    hasher.Write((unsigned char*)&hashJustWitness, hashJustWitness.size());
    hasher.Finalize((unsigned char*)&hashFull);
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        nValueOut += tx_out.nValue.GetAmount();
        if (!MoneyRange(tx_out.nValue.GetAmount()) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}
