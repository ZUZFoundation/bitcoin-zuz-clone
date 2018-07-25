// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

<<<<<<< HEAD
#include <tinyformat.h>
#include <util.h>
=======
#include "script/script.h"
#include "util.h"
#include "utilstrencodings.h"
>>>>>>> elements/alpha

#include <assert.h>
#include <stdio.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::REGTEST = "regtest";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
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
<<<<<<< HEAD
        nRPCPort = 4847;
=======
        networkID = CBaseChainParams::MAIN;
        nRPCPort = 8332;
        strDataDir = "alphamain";
>>>>>>> elements/alpha
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
<<<<<<< HEAD
        nRPCPort = 14847;
        strDataDir = "testnet3";
=======
        networkID = CBaseChainParams::TESTNET;
        nRPCPort = 4241;
        strDataDir = "alphatestnet3";
>>>>>>> elements/alpha
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
<<<<<<< HEAD
        nRPCPort = 18443;
        strDataDir = "regtest";
=======
        networkID = CBaseChainParams::REGTEST;
        strDataDir = "alpharegtest";
>>>>>>> elements/alpha
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
<<<<<<< HEAD
    bool fRegTest = gArgs.GetBoolArg("-regtest", false);
    bool fTestNet = gArgs.GetBoolArg("-testnet", false);
=======
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", true);
>>>>>>> elements/alpha

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (fRegTest)
        return CBaseChainParams::REGTEST;
    if (fTestNet)
        return CBaseChainParams::TESTNET;
    return CBaseChainParams::MAIN;
}
<<<<<<< HEAD
=======

CScript ScriptDestinationFromCommandLine()
{
    std::string sd = GetArg("-genesisscriptdestination", "");
    if (!sd.empty()) {
        if (IsHex(sd)) {
            std::vector<unsigned char> sd_raw(ParseHex(sd));
            return CScript(sd_raw.begin(), sd_raw.end());
        } else {
            fprintf(stderr, "Warning: Genesis script destination was not valid hex, ignoring it.\n");
        }
    }
    return CScript();
}

bool SelectBaseParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectBaseParams(network);
    return true;
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}
>>>>>>> elements/alpha
