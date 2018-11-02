// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

#include <tinyformat.h>
#include <util.h>

#include <assert.h>

const std::string CBaseChainParams::MAIN = CHAINPARAMS_OLD_MAIN;
const std::string CBaseChainParams::REGTEST = CHAINPARAMS_REGTEST;

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-chain=<chain>", strprintf(_("Use the chain <chain> (default: %s). Anything except main is allowed. Note that this affects where \"network specific\" files will be searched for, such as cookie files when using -cli."), CHAINPARAMS_REGTEST));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", strprintf(_("Equivalent to -chain=%s"), CHAINPARAMS_REGTEST));
        strUsage += HelpMessageOpt("-pubkeyprefix", strprintf(_("The byte prefix, in decimal, of the chain's base58 pubkey address. (default: %d)"), 235));
        strUsage += HelpMessageOpt("-scriptprefix", strprintf(_("The byte prefix, in decimal, of the chain's base58 script address. (default: %d)"), 75));
        strUsage += HelpMessageOpt("-secretprefix", strprintf(_("The byte prefix, in decimal, of the chain's base58 secret key encoding. (default: %d)"), 239));
        strUsage += HelpMessageOpt("-extpubkeyprefix", strprintf(_("The 4-byte prefix, in hex, of the chain's base58 extended public key encoding. (default: %s)"), "043587CF"));
        strUsage += HelpMessageOpt("-extprvkeyprefix", strprintf(_("The 4-byte prefix, in hex, of the chain's base58 extended private key encoding. (default: %s)"), "04358394"));
        strUsage += HelpMessageOpt("-blindedprefix", strprintf(_("The byte prefix, in decimal, of the chain's base58 script address. (default: %d)"), 4));
    }
}

/**
 * Main network
 */
class CBaseMainParams : public CBaseChainParams
{
public:
    CBaseMainParams()
    {
        nRPCPort = 4865;
    }
};

/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CBaseChainParams
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 14865;
        strDataDir = "testnet3";
    }
};

/*
 * Regression test
 */
class CBaseRegTestParams : public CBaseChainParams
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 18443;
        strDataDir = "regtest";
    }
};

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CBaseChainParams>(new CBaseMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CBaseChainParams>(new CBaseTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CBaseChainParams>(new CBaseRegTestParams());
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
}

std::string ChainNameFromCommandLine()
{
    bool fRegTest = gArgs.GetBoolArg("-regtest", false);
    bool fTestNet = gArgs.GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (fRegTest)
        return CBaseChainParams::REGTEST;
    if (fTestNet)
        return CBaseChainParams::TESTNET;
    return CBaseChainParams::MAIN;
}
