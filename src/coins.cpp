// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <consensus/consensus.h>
#include <random.h>
#ifndef HIM_NDEBUG
#include <util.h>
#endif

<<<<<<< HEAD
bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
=======
#include <assert.h>

#include <secp256k1.h>
#include <secp256k1_rangeproof.h>

/**
 * calculate number of bytes for the bitmask, and its number of non-zero bytes
 * each bit in the bitmask represents the availability of one output, but the
 * availabilities of the first two outputs are encoded separately
 */
void CCoins::CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const {
    unsigned int nLastUsedByte = 0;
    for (unsigned int b = 0; 2+b*8 < vout.size(); b++) {
        bool fZero = true;
        for (unsigned int i = 0; i < 8 && 2+b*8+i < vout.size(); i++) {
            if (!vout[2+b*8+i].IsNull()) {
                fZero = false;
                continue;
            }
        }
        if (!fZero) {
            nLastUsedByte = b + 1;
            nNonzeroBytes++;
        }
    }
    nBytes += nLastUsedByte;
}

bool CCoins::Spend(const COutPoint &out, CTxInUndo &undo) {
    if (out.n >= vout.size())
        return false;
    if (vout[out.n].IsNull())
        return false;
    undo = CTxInUndo(vout[out.n]);
    vout[out.n].SetNull();
    Cleanup();
    if (vout.size() == 0) {
        undo.nHeight = nHeight + 1;
        undo.fCoinBase = fCoinBase;
        undo.nVersion = this->nVersion;
    }
    return true;
}

bool CCoins::Spend(int nPos) {
    CTxInUndo undo;
    COutPoint out(0, nPos);
    return Spend(out, undo);
}


bool CCoinsView::GetCoins(const uint256 &txid, CCoins &coins) const { return false; }
bool CCoinsView::HaveCoins(const uint256 &txid) const { return false; }
COutPoint CCoinsView::GetWithdrawSpent(const std::pair<uint256, COutPoint> &outpoint) const { return COutPoint(); }
uint256 CCoinsView::GetBestBlock() const { return uint256(0); }
>>>>>>> elements/alpha
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return false; }
CCoinsViewCursor *CCoinsView::Cursor() const { return nullptr; }

bool CCoinsView::HaveCoin(const COutPoint &outpoint) const
{
    Coin coin;
    return GetCoin(outpoint, coin);
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }
<<<<<<< HEAD
bool CCoinsViewBacked::GetCoin(const COutPoint &outpoint, Coin &coin) const { return base->GetCoin(outpoint, coin); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
=======
bool CCoinsViewBacked::GetCoins(const uint256 &txid, CCoins &coins) const { return base->GetCoins(txid, coins); }
bool CCoinsViewBacked::HaveCoins(const uint256 &txid) const { return base->HaveCoins(txid); }
COutPoint CCoinsViewBacked::GetWithdrawSpent(const std::pair<uint256, COutPoint> &outpoint) const { return base->GetWithdrawSpent(outpoint); }
>>>>>>> elements/alpha
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
std::vector<uint256> CCoinsViewBacked::GetHeadBlocks() const { return base->GetHeadBlocks(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return base->BatchWrite(mapCoins, hashBlock); }
CCoinsViewCursor *CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }

SaltedOutpointHasher::SaltedOutpointHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn) : CCoinsViewBacked(baseIn), cachedCoinsUsage(0) {}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
}

<<<<<<< HEAD
CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint) const {
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
=======
static inline CCoinsMapKey make_txentry(const uint256 &txid) {
    return std::make_pair(txid, COutPoint());
}

CCoinsMap::const_iterator CCoinsViewCache::FetchCoins(const uint256 &txid) const {
    CCoinsMap::iterator it = cacheCoins.find(make_txentry(txid));
>>>>>>> elements/alpha
    if (it != cacheCoins.end())
        return it;
    Coin tmp;
    if (!base->GetCoin(outpoint, tmp))
        return cacheCoins.end();
<<<<<<< HEAD
    CCoinsMap::iterator ret = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(tmp))).first;
    if (ret->second.coin.IsSpent()) {
        // The parent only has an empty entry for this outpoint; we can consider our
=======
    CCoinsMap::iterator ret = cacheCoins.insert(std::make_pair(make_txentry(txid), CCoinsCacheEntry())).first;
    tmp.swap(ret->second.coins);
    if (ret->second.coins.IsPruned()) {
        // The parent only has an empty entry for this txid; we can consider our
>>>>>>> elements/alpha
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();
    return ret;
}

bool CCoinsViewCache::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it != cacheCoins.end()) {
        coin = it->second.coin;
        return !coin.IsSpent();
    }
    return false;
}

<<<<<<< HEAD
void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable()) return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite) {
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Adding new coin that replaces non-pruned entry");
=======
CCoinsModifier CCoinsViewCache::ModifyCoins(const uint256 &txid) {
    assert(!hasModifier);
    std::pair<CCoinsMap::iterator, bool> ret = cacheCoins.insert(std::make_pair(make_txentry(txid), CCoinsCacheEntry()));
    if (ret.second) {
        if (!base->GetCoins(txid, ret.first->second.coins)) {
            // The parent view does not have this entry; mark it as fresh.
            ret.first->second.coins.Clear();
            ret.first->second.flags = CCoinsCacheEntry::FRESH;
        } else if (ret.first->second.coins.IsPruned()) {
            // The parent view only has a pruned entry for this; mark it as fresh.
            ret.first->second.flags = CCoinsCacheEntry::FRESH;
>>>>>>> elements/alpha
        }
        fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
    }
    it->second.coin = std::move(coin);
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check) {
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Always set the possible_overwrite flag to AddCoin for coinbase txn, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
    }
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;
    cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    if (moveout) {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.flags & CCoinsCacheEntry::FRESH) {
        cacheCoins.erase(it);
    } else {
        it->second.flags |= CCoinsCacheEntry::DIRTY;
        it->second.coin.Clear();
    }
    return true;
}

static const Coin coinEmpty;

const Coin& CCoinsViewCache::AccessCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) {
        return coinEmpty;
    } else {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

COutPoint CCoinsViewCache::GetWithdrawSpent(const std::pair<uint256, COutPoint> &outpoint) const {
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it == cacheCoins.end()) {
        it = cacheCoins.insert(std::make_pair(outpoint, CCoinsCacheEntry())).first;
        it->second.withdrawSpent = base->GetWithdrawSpent(outpoint);
        it->second.flags |= CCoinsCacheEntry::WITHDRAW;
    }
    return it->second.withdrawSpent;
}

void CCoinsViewCache::MaybeSetWithdrawSpent(const std::pair<uint256, COutPoint> &outpoint, COutPoint spender) {
    CCoinsMap::iterator it = cacheCoins.find(outpoint);

    // If its already spent - dont overwrite, unless spender IsNull
    bool hadSpent;
    if (it == cacheCoins.end())
        hadSpent = !base->GetWithdrawSpent(outpoint).IsNull();
    else
        hadSpent = !it->second.withdrawSpent.IsNull();
    if (hadSpent && !spender.IsNull())
        return;

    if (it == cacheCoins.end()) {
        it = cacheCoins.insert(std::make_pair(outpoint, CCoinsCacheEntry())).first;
        if (!hadSpent)
            it->second.flags = CCoinsCacheEntry::FRESH;
    }
    it->second.withdrawSpent = spender;
    it->second.flags |= CCoinsCacheEntry::WITHDRAW | CCoinsCacheEntry::DIRTY;
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlockIn) {
<<<<<<< HEAD
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end(); it = mapCoins.erase(it)) {
        // Ignore non-dirty entries (optimization).
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY)) {
            continue;
        }
        CCoinsMap::iterator itUs = cacheCoins.find(it->first);
        if (itUs == cacheCoins.end()) {
            // The parent cache does not have an entry, while the child does
            // We can ignore it if it's both FRESH and pruned in the child
            if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent())) {
                // Otherwise we will need to create it in the parent
                // and move the data up and mark it as dirty
                CCoinsCacheEntry& entry = cacheCoins[it->first];
                entry.coin = std::move(it->second.coin);
                cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                entry.flags = CCoinsCacheEntry::DIRTY;
                // We can mark it FRESH in the parent if it was FRESH in the child
                // Otherwise it might have just been flushed from the parent's cache
                // and already exist in the grandparent
                if (it->second.flags & CCoinsCacheEntry::FRESH) {
                    entry.flags |= CCoinsCacheEntry::FRESH;
=======
    assert(!hasModifier);
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) { // Ignore non-dirty entries (optimization).
            bool fIsWithdraw = it->second.flags & CCoinsCacheEntry::WITHDRAW;
            CCoinsMap::iterator itUs = cacheCoins.find(it->first);
            if (itUs == cacheCoins.end()) {
                if ((fIsWithdraw && !it->second.withdrawSpent.IsNull()) ||
                        (!fIsWithdraw && !it->second.coins.IsPruned())) {
                    // The parent cache does not have an entry, while the child
                    // cache does have (a non-pruned) one. Move the data up, and
                    // mark it as fresh (if the grandparent did have it, we
                    // would have pulled it in at first GetCoins).
                    assert(it->second.flags & CCoinsCacheEntry::FRESH);
                    CCoinsCacheEntry& entry = cacheCoins[it->first];
                    entry.flags = CCoinsCacheEntry::DIRTY | CCoinsCacheEntry::FRESH;
                    if (fIsWithdraw) {
                        entry.withdrawSpent = it->second.withdrawSpent;
                        entry.flags |= CCoinsCacheEntry::WITHDRAW;
                    } else
                        entry.coins.swap(it->second.coins);
>>>>>>> elements/alpha
                }
            }
        } else {
            // Assert that the child cache entry was not marked FRESH if the
            // parent cache entry has unspent outputs. If this ever happens,
            // it means the FRESH flag was misapplied and there is a logic
            // error in the calling code.
            if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent()) {
                throw std::logic_error("FRESH flag misapplied to cache entry for base transaction with spendable outputs");
            }

            // Found the entry in the parent cache
            if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent()) {
                // The grandparent does not have an entry, and the child is
                // modified and being pruned. This means we can just delete
                // it from the parent.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                cacheCoins.erase(itUs);
            } else {
<<<<<<< HEAD
                // A normal modification.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                itUs->second.coin = std::move(it->second.coin);
                cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                // NOTE: It is possible the child has a FRESH flag here in
                // the event the entry we found in the parent is pruned. But
                // we must not copy that FRESH flag to the parent as that
                // pruned state likely still needs to be communicated to the
                // grandparent.
=======
                if ((itUs->second.flags & CCoinsCacheEntry::FRESH) &&
                        ((fIsWithdraw && it->second.withdrawSpent.IsNull()) || (!fIsWithdraw && it->second.coins.IsPruned()))) {
                    // The grandparent does not have an entry, and the child is
                    // modified and being pruned. This means we can just delete
                    // it from the parent.
                    cacheCoins.erase(itUs);
                } else {
                    // A normal modification.
                    if (fIsWithdraw)
                        itUs->second.withdrawSpent = it->second.withdrawSpent;
                    else
                        itUs->second.coins.swap(it->second.coins);
                    itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                }
>>>>>>> elements/alpha
            }
        }
    }
    hashBlock = hashBlockIn;
    return true;
}

bool CCoinsViewCache::Flush() {
    bool fOk = base->BatchWrite(cacheCoins, hashBlock);
    cacheCoins.clear();
    cachedCoinsUsage = 0;
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& hash)
{
    CCoinsMap::iterator it = cacheCoins.find(hash);
    if (it != cacheCoins.end() && it->second.flags == 0) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        cacheCoins.erase(it);
    }
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

extern secp256k1_context* secp256k1_bitcoin_verify_context;

bool CCoinsViewCache::VerifyAmounts(const CTransaction& tx, const CAmount& excess) const
{
    CAmount nPlainAmount = excess;
    std::vector<unsigned char> vchData;
    std::vector<unsigned char *> vpchCommitsIn, vpchCommitsOut;
    bool fNullRangeproof = false;
    vchData.resize(CTxOutValue::nCommitmentSize * (tx.vin.size() + tx.vout.size()));
    unsigned char *p = vchData.data();
    if (!tx.IsCoinBase())
    {
        for (size_t i = 0; i < tx.vin.size(); ++i)
        {
            const CTxOutValue& val = GetOutputFor(tx.vin[i]).nValue;
            if (val.IsAmount())
                nPlainAmount -= val.GetAmount();
            else
            {
                assert(val.vchCommitment.size() == CTxOutValue::nCommitmentSize);
                memcpy(p, &val.vchCommitment[0], CTxOutValue::nCommitmentSize);
                vpchCommitsIn.push_back(p);
                p += CTxOutValue::nCommitmentSize;
            }
        }
    }
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
        const CTxOutValue& val = tx.vout[i].nValue;
        assert(val.vchCommitment.size() == CTxOutValue::nCommitmentSize);
        if (val.vchNonceCommitment.size() > CTxOutValue::nCommitmentSize || val.vchRangeproof.size() > 5000)
            return false;
        if (val.IsAmount())
            nPlainAmount += val.GetAmount();
        else
        {
            memcpy(p, &val.vchCommitment[0], CTxOutValue::nCommitmentSize);
            vpchCommitsOut.push_back(p);
            p += CTxOutValue::nCommitmentSize;

            if (val.vchRangeproof.empty())
                fNullRangeproof = true;
        }
    }

<<<<<<< HEAD
    CAmount nResult = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        nResult += AccessCoin(tx.vin[i].prevout).out.nValue;
=======
    // If there are no encrypted input or output values, we can do simple math
    if (vpchCommitsIn.size() + vpchCommitsOut.size() == 0)
        return (nPlainAmount == 0);

    if (!secp256k1_pedersen_verify_tally(secp256k1_bitcoin_verify_context, vpchCommitsIn.data(), vpchCommitsIn.size(), vpchCommitsOut.data(), vpchCommitsOut.size(), nPlainAmount))
        return false;

    // Rangeproof is optional in this case
    if ((!vpchCommitsIn.empty()) && vpchCommitsOut.size() == 1 && nPlainAmount <= 0 && fNullRangeproof)
        return true;
>>>>>>> elements/alpha

    uint64_t min_value, max_value;
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
        const CTxOutValue& val = tx.vout[i].nValue;
        if (val.IsAmount())
            continue;
        if (!secp256k1_rangeproof_verify(secp256k1_bitcoin_verify_context, &min_value, &max_value, &val.vchCommitment[0], val.vchRangeproof.data(), val.vchRangeproof.size()))
            return false;
    }

    return true;
}

bool CCoinsViewCache::VerifyAmounts(const CTransaction& tx) const
{
    const CAmount& excess = tx.nTxFee;
    return VerifyAmounts(tx, excess);
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!HaveCoin(tx.vin[i].prevout)) {
                return false;
            }
        }
    }
    return true;
}

<<<<<<< HEAD
static const size_t MIN_TRANSACTION_OUTPUT_WEIGHT = ::GetSerializeSize(CTxOut(), SER_NETWORK, PROTOCOL_VERSION);
static const size_t MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT;
=======
double CCoinsViewCache::GetPriority(const CTransaction &tx, int nHeight) const
{
    if (tx.IsCoinBase())
        return 0.0;
    double dResult = 0.0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        const CCoins* coins = AccessCoins(txin.prevout.hash);
        assert(coins);
        if (!coins->IsAvailable(txin.prevout.n)) continue;
        int nOffset = 0;
        if (coins->vout[txin.prevout.n].scriptPubKey.IsWithdrawOutput() && txin.scriptSig.IsPushOnly() && txin.scriptSig.size() > 1 && txin.scriptSig.back() == OP_1) {
            // Fraud/reorg proofs get a significant priority bump
            nOffset = 10000;
        } else if (coins->vout[txin.prevout.n].scriptPubKey.IsWithdrawLock(0))
            // Coins moving to this chain get a priority bump
            nOffset = 100;
        int nCoinsHeight = coins->nHeight == 0x7fffffff ? nHeight + 1 : coins->nHeight;
        if (nCoinsHeight < nHeight + nOffset) {
            const CTxOutValue& val = coins->vout[txin.prevout.n].nValue;
            // FIXME: This assumes all blinded values are COIN
            CAmount nAmount = COIN;
            if (val.IsAmount())
                nAmount = val.GetAmount();
            dResult += double(nAmount + nOffset) * double(nHeight - nCoinsHeight + nOffset);
        }
    }
    return tx.ComputePriority(dResult);
}

CCoinsModifier::CCoinsModifier(CCoinsViewCache& cache_, CCoinsMap::iterator it_) : cache(cache_), it(it_) {
    assert(!cache.hasModifier);
    cache.hasModifier = true;
}
>>>>>>> elements/alpha

const Coin& AccessByTxid(const CCoinsViewCache& view, const uint256& txid)
{
    COutPoint iter(txid, 0);
#ifndef HIM_NDEBUG
    LogPrintf("HIM : AccessByTxid iter.n : %i", iter.n);
#endif
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {
        const Coin& alternate = view.AccessCoin(iter);
        if (!alternate.IsSpent()) return alternate;
        ++iter.n;
    }
    return coinEmpty;
}
