#include <callrpc.h>
#include <chainparamsbase.h>
#include <util.h>
#include <utilstrencodings.h>
#include <rpc/protocol.h>
#include <boost/asio.hpp>


using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace RPC;

#define _(x) std::string(x) /* Keep the _() around in case gettext or such will be used later to translate non-UI */

UniValue CallRPC(const string& strMethod, const UniValue &params, string port)
{
    if (gArgs.GetArg("-rpcuser", "") == "" || gArgs.GetArg("-rpcpassword", "") == "")
        throw runtime_error(strprintf(
            _("You must set rpcuser=<rpcuser> and rpcpassword=<password> in the configuration file:\n%s\n"
              "If the file does not exist, create it with owner-readable-only file permissions."),
                GetConfigFile(gArgs.GetArg("-conf", /*HIM_REVISIT*/BITCOIN_CONF_FILENAME)).string().c_str()));

    // Connect to localhost
    bool fUseSSL = gArgs.GetArg("-rpcssl", false);
    asio::io_service io_service;
    ssl::context context(io_service, ssl::context::sslv23);
    context.set_options(ssl::context::no_sslv2 | ssl::context::no_sslv3);
    asio::ssl::stream<asio::ip::tcp::socket> sslStream(io_service, context);
    SSLIOStreamDevice<asio::ip::tcp> d(sslStream, fUseSSL);
    iostreams::stream< SSLIOStreamDevice<asio::ip::tcp> > stream(d);

    if (port == "")
        port = gArgs.GetArg("-rpcport", itostr(BaseParams().RPCPort()));
    const bool fConnected = d.connect(gArgs.GetArg("-rpcconnect", "127.0.0.1"), port);
    if (!fConnected)
        throw CConnectionFailed("couldn't connect to server");

    // HTTP basic authentication
    string strUserPass64 = EncodeBase64(gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", ""));
    map<string, string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

    // Send request
    string strRequest = JSONRPCRequestObj(strMethod, params, 1).write();
    string strPost = HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive HTTP reply status
    int nProto = 0;
    int nStatus = ReadHTTPStatus(stream, nProto);

    // Receive HTTP reply message headers and body
    map<string, string> mapHeaders;
    string strReply;
    ReadHTTPMessage(stream, mapHeaders, strReply, nProto, std::numeric_limits<size_t>::max());

    if (nStatus == HTTP_UNAUTHORIZED)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND && nStatus != HTTP_INTERNAL_SERVER_ERROR)
        throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
    else if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    UniValue valReply;
    valReply.push_back(strReply);

    return valReply;
}

bool IsConfirmedBitcoinBlock(const uint256& hash, int nMinConfirmationDepth)
{
    try
    {
        UniValue params;
        params.push_back(hash.GetHex());
        UniValue reply = CallRPC("getblock", params, gArgs.GetArg("-rpcconnectport", "18332"));
        if (find_value(reply, "error").getType() != UniValue::VType::VNULL)
        {
            LogPrintf("IsConfirmedBitcoinBlock error is not UniValue::VType::VNULL \n");
            return false;
        }
        UniValue result = find_value(reply, "result");
        if (result.getType() != UniValue::VType::VOBJ)
        {
            LogPrintf("IsConfirmedBitcoinBlock type is not UniValue::VType::VOBJ \n");
            return false;
        }
        result = find_value(result.get_obj(), "confirmations");
        if(!result.isNum())
        {
            LogPrintf("IsConfirmedBitcoinBlock result is not number \n");
            return false;
        }

        LogPrintf("IsConfirmedBitcoinBlock result.get_int64() : ", result.get_int64());
        LogPrintf("\nIsConfirmedBitcoinBlock nMinConfirmationDepth : ", nMinConfirmationDepth);
        LogPrintf("\n");

        return result.get_int64() >= nMinConfirmationDepth;
    }
    catch (CConnectionFailed& e)
    {
        LogPrintf("ERROR: Lost connection to alphad RPC, you will want to restart after fixing this!\n");
        return false;
    }
    catch (...)
    {
        LogPrintf("ERROR: Failure connecting to alphad RPC, you will want to restart after fixing this!\n");
        return false;
    }
    return true;
}
