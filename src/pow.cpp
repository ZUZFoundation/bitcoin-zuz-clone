// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

#ifndef HIM_NDEBUG
#include <util.h>
#endif

unsigned int static DarkGravityWave(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    /* current difficulty formula, dash - DarkGravity v3, written by Evan Duffield - evan@dash.org */
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    int64_t nPastBlocks = 24;

    // make sure we have at least (nPastBlocks + 1) blocks, otherwise just return powLimit
    if (!pindexLast || pindexLast->nHeight < nPastBlocks)
    {
        return bnPowLimit.GetCompact();
    }

    //    if (params.fPowAllowMinDifficultyBlocks && (
    //        // testnet ...
    //        (params.hashDevnetGenesisBlock.IsNull() &&
    //         pindexLast->nChainWork >= UintToArith256(uint256S("0x000000000000000000000000000000000000000000000000003e9ccfe0e03e01"))) ||
    //        // or devnet
    //        !params.hashDevnetGenesisBlock.IsNull())) {
    //        // NOTE: 000000000000000000000000000000000000000000000000003e9ccfe0e03e01 is the work of the "wrong" chain,
    //        // so this rule activates there immediately and new blocks with high diff from that chain are going
    //        // to be rejected by updated nodes. Note, that old nodes are going to reject blocks from updated nodes
    //        // after the "right" chain reaches this amount of work too. This is a temporary condition which should
    //        // be removed when we decide to hard-fork testnet again.
    //        // TODO: remove "testnet+work OR devnet" part on next testnet hard-fork
    //        // Special difficulty rule for testnet/devnet:
    //        // If the new block's timestamp is more than 2* 2.5 minutes
    //        // then allow mining of a min-difficulty block.
    //        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
    //            return bnPowLimit.GetCompact();
    //    }

    const CBlockIndex *pindex = pindexLast;
    arith_uint256 bnPastTargetAvg;

    for (unsigned int nCountBlocks = 1; nCountBlocks <= nPastBlocks; nCountBlocks++)
    {
        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
        if (nCountBlocks == 1)
        {
            bnPastTargetAvg = bnTarget;
        }
        else
        {
            // NOTE: that's not an average really...
            bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
        }

        if(nCountBlocks != nPastBlocks)
        {
            assert(pindex->pprev); // should never fail
            pindex = pindex->pprev;
        }
    }

    arith_uint256 bnNew(bnPastTargetAvg);

    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindex->GetBlockTime();
    // NOTE: is this accurate? nActualTimespan counts it for (nPastBlocks - 1) blocks only...
    int64_t nTargetTimespan = nPastBlocks * params.nPowTargetSpacing;

    if (nActualTimespan < nTargetTimespan / 3)
        nActualTimespan = nTargetTimespan / 3;
    if (nActualTimespan > nTargetTimespan * 3)
        nActualTimespan = nTargetTimespan * 3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPowLimit)
    {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}


unsigned int GetNextWorkRequiredBTC(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    if(pindexLast->nHeight + 1 >= params.zuzPowDGWHeight)
    {
        return DarkGravityWave(pindexLast, pblock, params);
    }
    else
    {
        return GetNextWorkRequiredBTC(pindexLast, pblock, params);
    }
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;

#ifndef HIM_NDEBUG
    LogPrintf("HIM : nActualTimespan : %i", nActualTimespan);
    LogPrintf("HIM : pindexLast->GetBlockTime() : %i", pindexLast->GetBlockTime());
    LogPrintf("HIM : nFirstBlockTime : %i", nFirstBlockTime);
    LogPrintf("HIM : params.nPowTargetTimespan : %i", params.nPowTargetTimespan);
#endif


    if (nActualTimespan < params.nPowTargetTimespan/10)
        nActualTimespan = params.nPowTargetTimespan/10;
    if (nActualTimespan > params.nPowTargetTimespan*10)
        nActualTimespan = params.nPowTargetTimespan*10;

#ifndef HIM_NDEBUG
    LogPrintf("HIM : After nActualTimespan : %i", nActualTimespan);
#endif

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
