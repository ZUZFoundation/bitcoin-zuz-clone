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
<<<<<<< HEAD
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
=======
        str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24));
    if (~nSequence)
>>>>>>> elements/alpha
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CTxOutValue& valueIn, CScript scriptPubKeyIn)
{
    nValue = valueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
<<<<<<< HEAD
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
=======
    return strprintf("CTxOut(nValue=%s, scriptPubKey=%s)", (nValue.IsAmount() ? strprintf("%d.%08d", nValue.GetAmount() / COIN, nValue.GetAmount() % COIN) : std::string("UNKNOWN")), scriptPubKey.ToString().substr(0,30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nTxFee(0), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), vin(tx.vin), nTxFee(tx.nTxFee), vout(tx.vout), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    if (IsCoinBase()) {
        return SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION);
    } else {
        return SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_VERSION_MASK_NO_WITNESS);
    }
>>>>>>> elements/alpha
}

uint256 CTransaction::ComputeHash() const
{
<<<<<<< HEAD
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
CTransaction::CTransaction() : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), hash() {}
CTransaction::CTransaction(const CMutableTransaction &tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash(ComputeHash()) {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
=======
    bool maybeBitcoinTx = true;
    for (unsigned int i = 0; i < vout.size(); i++)
        if (!vout[i].nValue.IsAmount())
            maybeBitcoinTx = false;
    if (maybeBitcoinTx)
        *const_cast<uint256*>(&hashBitcoin) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_VERSION_MASK_BITCOIN_TX);

    if (IsCoinBase()) {
        *const_cast<uint256*>(&hash) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION);
    } else {
        *const_cast<uint256*>(&hash) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_VERSION_MASK_NO_WITNESS);
    }
    *const_cast<uint256*>(&hashWitness) = SerializeHash(*this, SER_GETHASH, PROTOCOL_VERSION | SERIALIZE_VERSION_MASK_ONLY_WITNESS);
    // Update full hash combining the normalized txid with the hash of the witness
    CHash256 hasher;
    hasher.Write((unsigned char*)&hash, hash.size());
    hasher.Write((unsigned char*)&hashWitness, hashWitness.size());
    hasher.Finalize((unsigned char*)&hashFull);
}

CTransaction::CTransaction() : hash(0), hashFull(0), nVersion(CTransaction::CURRENT_VERSION), vin(), nTxFee(0), vout(), nLockTime(0) { }

CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), vin(tx.vin), nTxFee(tx.nTxFee), vout(tx.vout), nLockTime(tx.nLockTime) {
    UpdateHash();
}

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<CAmount*>(&nTxFee) = tx.nTxFee;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256*>(&hash) = tx.hash;
    *const_cast<uint256*>(&hashFull) = tx.hashFull;
    return *this;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
>>>>>>> elements/alpha
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u, fee=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
<<<<<<< HEAD
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
=======
        nLockTime, nTxFee);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
>>>>>>> elements/alpha
    return str;
}
