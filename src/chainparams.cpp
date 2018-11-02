// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>
#include <arith_uint256.h>
#include <base58.h>
#include "issuance.h"

#include "crypto/sha256.h"

#include <boost/assign/list_of.hpp>

// Safer for users if they load incorrect parameters via arguments.
static std::vector<unsigned char> CommitToArguments(const Consensus::Params& params, const std::string& networkID)
{
    CSHA256 sha2;
    unsigned char commitment[32];
    sha2.Write((const unsigned char*)networkID.c_str(), networkID.length());
    sha2.Write((const unsigned char*)HexStr(params.fedpegScript).c_str(), HexStr(params.fedpegScript).length());
    sha2.Write((const unsigned char*)HexStr(params.signblockscript).c_str(), HexStr(params.signblockscript).length());
    sha2.Finalize(commitment);
    return std::vector<unsigned char>(commitment, commitment + 32);
}

static CScript StrHexToScriptWithDefault(std::string strScript, const CScript defaultScript)
{
    CScript returnScript;
    if (!strScript.empty()) {
        std::vector<unsigned char> scriptData = ParseHex(strScript);
        returnScript = CScript(scriptData.begin(), scriptData.end());
    } else {
        returnScript = defaultScript;
    }
    return returnScript;
}

static CBlock CreateGenesisBlock(const Consensus::Params& params, const std::string& networkID, uint32_t nTime, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 503349247 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
   /*
    // Any consensus-related values that are command-line set can be added here for anti-footgun
    txNew.vin[0].scriptSig = CScript(CommitToArguments(params, networkID));
    txNew.vout.clear();
    txNew.vout.push_back(CTxOut(CAsset(), 0, CScript() << OP_RETURN));
    */

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.proof = CProof(params.signblockscript, CScript());
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/** Add an issuance transaction to the genesis block. Typically used to pre-issue
 * the policyAsset of a blockchain. The genesis block is not actually validated,
 * so this transaction simply has to match issuance structure. */
static void AppendInitialIssuance(CBlock& genesis_block, const COutPoint& prevout, const uint256& contract, const int64_t asset_outputs, const int64_t asset_values, const int64_t reissuance_outputs, const int64_t reissuance_values, const CScript& issuance_destination) {

    uint256 entropy;
    GenerateAssetEntropy(entropy, prevout, contract);

    CAsset asset;
    CalculateAsset(asset, entropy);

    // Re-issuance of policyAsset is always unblinded
    CAsset reissuance;
    CalculateReissuanceToken(reissuance, entropy, false);

    // Note: Genesis block isn't actually validated, outputs are entered into utxo db only
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vin[0].prevout = prevout;
    txNew.vin[0].assetIssuance.assetEntropy = contract;
    txNew.vin[0].assetIssuance.nAmount = asset_values*asset_outputs;
    txNew.vin[0].assetIssuance.nInflationKeys = reissuance_values*reissuance_outputs;

    for (unsigned int i = 0; i < asset_outputs; i++) {
        txNew.vout.push_back(CTxOut(asset, asset_values, issuance_destination));
    }
    for (unsigned int i = 0; i < reissuance_outputs; i++) {
        txNew.vout.push_back(CTxOut(reissuance, reissuance_values, issuance_destination));
    }

    genesis_block.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis_block.hashMerkleRoot = BlockMerkleRoot(genesis_block);
}

void CChainParams::UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}



/**
 * Custom chain params
 */
class CCustomParams : public CChainParams {

protected:
    void UpdateFromArgs()
    {
        consensus.nSubsidyHalvingInterval = GetArg("-con_nsubsidyhalvinginterval", 150);
        // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Height = GetArg("-con_bip34height", 100000000);
        consensus.BIP34Hash = uint256S(GetArg("-con_bip34hash", "0x00"));
        consensus.BIP65Height = GetArg("-con_bip65height", 1351);
        consensus.BIP66Height = GetArg("-con_bip66height", 1251);
        consensus.powLimit = uint256S(GetArg("-con_powlimit", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.parentChainPowLimit = uint256S(GetArg("-con_parentpowlimit", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.nPowTargetTimespan = GetArg("-con_npowtargettimespan", 14 * 24 * 60 * 60); // two weeks
        consensus.nPowTargetSpacing = GetArg("-con_npowtargetspacing", 10 * 60);
        consensus.fPowAllowMinDifficultyBlocks = GetBoolArg("-con_fpowallowmindifficultyblocks", true);
        consensus.fPowNoRetargeting = GetBoolArg("-con_fpownoretargeting", true);
        consensus.nRuleChangeActivationThreshold = GetArg("-con_nrulechangeactivationthreshold", 108); // 75% for testchains
        consensus.nMinerConfirmationWindow = GetArg("-con_nminerconfirmationwindow", 144); // Faster than normal for custom (144 instead of 2016)

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S(GetArg("-con_nminimumchainwork", "0x00"));
        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S(GetArg("-con_defaultassumevalid", "0x00"));
        consensus.pegin_min_depth = GetArg("-peginconfirmationdepth", DEFAULT_PEGIN_CONFIRMATION_DEPTH);
        consensus.mandatory_coinbase_destination = StrHexToScriptWithDefault(GetArg("-con_mandatorycoinbase", ""), CScript()); // Blank script allows any coinbase destination
        consensus.parent_chain_signblockscript = StrHexToScriptWithDefault(GetArg("-con_parent_chain_signblockscript", ""), CScript());
        consensus.parent_pegged_asset.SetHex(GetArg("-con_parent_pegged_asset", "0x00"));

        // bitcoin regtest is the parent chain by default
        parentGenesisBlockHash = uint256S(GetArg("-parentgenesisblockhash", "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        initialFreeCoins = GetArg("-initialfreecoins", 0);
        initial_reissuance_tokens = GetArg("-initialreissuancetokens", 0);
        consensus.has_parent_chain = GetBoolArg("-con_has_parent_chain", true);
        // Either it has a parent chain or not
        const bool parent_genesis_is_null = parentGenesisBlockHash == uint256();
        assert(consensus.has_parent_chain != parent_genesis_is_null);

        const CScript default_script(CScript() << OP_TRUE);
        consensus.signblockscript = StrHexToScriptWithDefault(GetArg("-signblockscript", ""), default_script);
        consensus.fedpegScript = StrHexToScriptWithDefault(GetArg("-fedpegscript", ""), default_script);

        nDefaultPort = GetArg("-ndefaultport", 7042);
        nPruneAfterHeight = GetArg("-npruneafterheight", 1000);
        fMiningRequiresPeers = GetBoolArg("-fminingrequirespeers", false);
        fDefaultConsistencyChecks = GetBoolArg("-fdefaultconsistencychecks", true);
        fRequireStandard = GetBoolArg("-frequirestandard", false);
        fMineBlocksOnDemand = GetBoolArg("-fmineblocksondemand", true);
        anyonecanspend_aremine = GetBoolArg("-anyonecanspendaremine", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, GetArg("-pubkeyprefix", 235));
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, GetArg("-scriptprefix", 75));
        base58Prefixes[BLINDED_ADDRESS]= std::vector<unsigned char>(1, GetArg("-blindedprefix", 4));
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, GetArg("-secretprefix", 239));

        std::string extpubprefix = GetArg("-extpubkeyprefix", "043587CF");
        if (!IsHex(extpubprefix) || extpubprefix.size() != 8) {
            assert("-extpubkeyprefix must be hex string of length 8" && false);
        }
        base58Prefixes[EXT_PUBLIC_KEY] = ParseHex(extpubprefix);

        std::string extprvprefix = GetArg("-extprvkeyprefix", "04358394");
        if (!IsHex(extprvprefix) || extprvprefix.size() != 8) {
            assert("-extprvkeyprefix must be hex string of length 8" && false);
        }
        base58Prefixes[EXT_SECRET_KEY] = ParseHex(extprvprefix);
        base58Prefixes[PARENT_PUBKEY_ADDRESS] = std::vector<unsigned char>(1, GetArg("-parentpubkeyprefix", 111));
        base58Prefixes[PARENT_SCRIPT_ADDRESS] = std::vector<unsigned char>(1, GetArg("-parentscriptprefix", 196));

    }

public:
    CCustomParams(const std::string& chain) : CChainParams(chain)
    {
        this->UpdateFromArgs();

        if (!anyonecanspend_aremine) {
            assert("Anyonecanspendismine was marked as false, but they are in the genesis block"
                    && initialFreeCoins == 0);
        }

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        // Generate pegged Bitcoin asset
        std::vector<unsigned char> commit = CommitToArguments(consensus, strNetworkID);
        uint256 entropy;
        GenerateAssetEntropy(entropy,  COutPoint(uint256(commit), 0), parentGenesisBlockHash);
        CalculateAsset(consensus.pegged_asset, entropy);

        genesis = CreateGenesisBlock(consensus, strNetworkID, 1296688602, 1);
        if (initialFreeCoins != 0 || initial_reissuance_tokens != 0) {
            AppendInitialIssuance(genesis, COutPoint(uint256(commit), 0), parentGenesisBlockHash, (initialFreeCoins > 0) ? 1 : 0, initialFreeCoins, (initial_reissuance_tokens > 0) ? 1 : 0, initial_reissuance_tokens, CScript() << OP_TRUE);
        }
        consensus.hashGenesisBlock = genesis.GetHash();



        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            (     0, consensus.hashGenesisBlock),
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Zuzcoin :  A smart and stable crypto currency";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

CScript CChainParams::zuzMultiSigScript(uint32_t lockTime) const
{
//#ifndef HIM_NDEBUG
//    std::cout << " HIM : zuzMultiSigScript " << std::endl;
//#endif
    assert(zuzPreminePubkeys.size() == 1);
    CScript redeemScript;

    CBitcoinAddress address(zuzPreminePubkeys.at(0));
    assert(address.IsValid());
    assert(address.IsScript());

    CScriptID scriptID = boost::get<CScriptID>(address.Get());

//#ifndef HIM_NDEBUG
//    std::cout << " HIM : zuzMultiSigScript scriptID : " << scriptID.GetHex() << std::endl;
//#endif

    redeemScript = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;



    /** multisig
    //Not using for now--------------------------------------------------
    if (lockTime > 0)
    {
        redeemScript << lockTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    }
    //------------------------------------------------------------------

    redeemScript << 1; // minimum number of valid sigatures require.

    for (const std::string& pubkey : zuzPreminePubkeys)
    {
        redeemScript << ToByteVector(ParseHex(pubkey));
    }

    redeemScript << 1 << OP_CHECKMULTISIG; // Total number of signatures provided.
    **/

    return redeemScript;
}

bool CChainParams::IsPremineAddressScript(const CScript& scriptPubKey, int height) const
{

//#ifndef HIM_NDEBUG
//    std::cout << " HIM : IsPremineAddressScript height : " << height << std::endl;
//#endif

    assert(height <= consensus.zuzPremineChainHeight);

    for (const std::string& addr : zuzPreminePubkeys)
    {

         CBitcoinAddress address(addr.c_str());
         assert(address.IsValid());
         assert(address.IsScript());

         CScriptID scriptID = boost::get<CScriptID>(address.Get());

         CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;


//#ifndef HIM_NDEBUG
//         std::cout << " HIM : IsPremineAddressScript scriptID : " << scriptID.GetHex() << std::endl;

//#endif

         if (script == scriptPubKey)
             return true;
    }

    // CScript redeemScript = zuzMultiSigScript();

    return false;

}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.zuzSubsidyChangeThreashold = 50000; // Block height when subsidy will be changed first time.
        consensus.zuzThresholdChangefactorValue = 100000;
        consensus.zuzPremineChainHeight = 1000;
        consensus.zuzPowDGWHeight = 400;
        consensus.zuzPremineEnforcePubKeys = true;
        zuzPreminePubkeys =
        {"MTUiEzuUT4R5wdfCToTbddnPJ839yLWWZb"}; //nico server : MTUiEzuUT4R5wdfCToTbddnPJ839yLWWZb;
                                                // my : MJ2UNWH1jHwabJPSnq9gdZ9RHDNCgJTDLn
                                                //
        consensus.BIP16Height = 0; // always enforce P2SH
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 1 * 24 * 60 * 60; // 1 days
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 684; // 95% of 2160
        consensus.nMinerConfirmationWindow = 720; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000002000400");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000005f59d403ec64fb527185bf7ed59460503d6789107aa767ba29b9499624"); //506067

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        nDefaultPort = 4848;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1528110003, 55912560, 0x1e007fff, 1, 50 * COIN);


        if (false && genesis.GetHash() != consensus.hashGenesisBlock)
        {
            printf("Searching for genesis block...\n");
            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
            arith_uint256 hashTarget;
            hashTarget.SetCompact(genesis.nBits);

            arith_uint256 thash;

            while(1)
            {
                genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
                thash = UintToArith256(genesis.GetHash());
                if (thash <= hashTarget)
                    break;
                if ((genesis.nNonce & 0xFFF) == 0)
                {
                    printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
                std::cout << ". ";
            }
            printf("genesis.nTime = %u \n", genesis.nTime);
            printf("genesis.nNonce = %u \n", genesis.nNonce);
            printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        }


        LogPrintf("consensus.hashGenesisBlock : %s", consensus.hashGenesisBlock.GetHex());
        LogPrintf("genesis.hashMerkleRoot     : %s", genesis.hashMerkleRoot.GetHex());
        LogPrintf("genesis.nNonce             : %d", genesis.nNonce);


        std::cout << genesis.GetHash().ToString() << std::endl;
        std::cout << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << genesis.nNonce << std::endl;


        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000005f59d403ec64fb527185bf7ed59460503d6789107aa767ba29b9499624"));
        assert(genesis.hashMerkleRoot == uint256S("0x3885fb409fe83cb0257fc642f3f3cc7c2678f960c118478e3231dd352fc86039"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they dont support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        // vSeeds.emplace_back("seed.zuzcoin.sipa.be"); // Pieter Wuille, only supports x1, x5, x9, and xd
        // vSeeds.emplace_back("dnsseed.bluematt.me"); // Matt Corallo, only supports x9
        // vSeeds.emplace_back("dnsseed.zuzcoin.dashjr.org"); // Luke Dashjr
        // vSeeds.emplace_back("seed.zuzcoinstats.com"); // Christian Decker, supports x1 - xf
        // vSeeds.emplace_back("seed.zuzcoin.jonasschnelli.ch"); // Jonas Schnelli, only supports x1, x5, x9, and xd
        // vSeeds.emplace_back("seed.btc.petertodd.org"); // Peter Todd, only supports x1, x5, x9, and xd

        //base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,40); // Prefix : H
        //base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50); // Prefix : M

        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        vFixedSeeds.clear();
        vSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                //{ 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 0000000000000000002d6cca6761c99b3c2e936f9a0e304b7c7651a993f461de (height 506081).
            1528110003, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            10         // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Custom chain params
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.zuzSubsidyChangeThreashold = 50000; // Block height when subsidy will be changed first time.
        consensus.zuzThresholdChangefactorValue = 100000;
        consensus.zuzPremineChainHeight = 0;
        consensus.zuzPowDGWHeight = 20;
        consensus.zuzPremineEnforcePubKeys = false;

        consensus.BIP16Height = 0;
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        //consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 1 * 24 * 60 * 60; // 1 days
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 540; // 75% for testchains
        consensus.nMinerConfirmationWindow = 720; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00"); //1135275

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 14848;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1528110103, 38573647, 0x1d0f0000, 1, 50 * COIN);

        if (false && genesis.GetHash() != consensus.hashGenesisBlock)
        {
            printf("Searching for genesis block...\n");
            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
            arith_uint256 hashTarget;
            hashTarget.SetCompact(genesis.nBits);

            arith_uint256 thash;

            while(1)
            {
                genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
                thash = UintToArith256(genesis.GetHash());
                if (thash <= hashTarget)
                    break;
                if ((genesis.nNonce & 0xFFF) == 0)
                {
                    printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                }
                ++genesis.nNonce;
                if (genesis.nNonce == 0)
                {
                    printf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
                std::cout << ". ";
            }
            printf("genesis.nTime = %u \n", genesis.nTime);
            printf("genesis.nNonce = %u \n", genesis.nNonce);
            printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        }


        LogPrintf("consensus.hashGenesisBlock : %s", consensus.hashGenesisBlock.GetHex());
        LogPrintf("genesis.hashMerkleRoot     : %s", genesis.hashMerkleRoot.GetHex());
        LogPrintf("genesis.nNonce             : %d", genesis.nNonce);


        std::cout << genesis.GetHash().ToString() << std::endl;
        std::cout << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << genesis.nNonce << std::endl;



        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000000e98794953fc94a61e3dca0fc75867f7827d79be79acda1cf983a86698"));
        assert(genesis.hashMerkleRoot == uint256S("0x3885fb409fe83cb0257fc642f3f3cc7c2678f960c118478e3231dd352fc86039"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // vSeeds.emplace_back("testnet-seed.zuzcoin.jonasschnelli.ch");
        // vSeeds.emplace_back("seed.tbtc.petertodd.org");
        // vSeeds.emplace_back("seed.testnet.zuzcoin.sprovoost.nl");
        // vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                //{546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 000000000000033cfa3c975eb83ecf2bb4aaedf68e6d279f6ed2b427c64caff9 (height 1260526)
            1528110103,
            0,
            3
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.zuzSubsidyChangeThreashold = 50; // Block height when subsidy will be changed first time.
        consensus.zuzThresholdChangefactorValue = 100;
        consensus.zuzPremineChainHeight = 10;
        consensus.zuzPowDGWHeight = 0;
        consensus.zuzPremineEnforcePubKeys = false;

        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 1 * 24 * 60 * 60; // 1 days
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        // Generate pegged Bitcoin asset
        std::vector<unsigned char> commit = CommitToArguments(consensus, strNetworkID);
        uint256 entropy;
        GenerateAssetEntropy(entropy,  COutPoint(uint256(commit), 0), parentGenesisBlockHash);
        CalculateAsset(consensus.pegged_asset, entropy);

        genesis = CreateGenesisBlock(consensus, strNetworkID, 1296688602, 1);
        if (initialFreeCoins != 0 || initial_reissuance_tokens != 0) {
            AppendInitialIssuance(genesis, COutPoint(uint256(commit), 0), parentGenesisBlockHash, (initialFreeCoins > 0) ? 1 : 0, initialFreeCoins, (initial_reissuance_tokens > 0) ? 1 : 0, initial_reissuance_tokens, CScript() << OP_TRUE);
        }
        consensus.hashGenesisBlock = genesis.GetHash();



        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                //{0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

//HIM_REVISIT
/**
 * Use base58 and other old configurations for outdated unittests
 */
/*
class CMainParams : public CCustomParams {
public:
    CMainParams(const std::string& chain) : CCustomParams(chain)
    {
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[BLINDED_ADDRESS]= std::vector<unsigned char>(1,11);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[PARENT_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[PARENT_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    }
};

*/

const std::vector<std::string> CChainParams::supportedChains =
    boost::assign::list_of
    ( CHAINPARAMS_REGTEST )
    ;

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
