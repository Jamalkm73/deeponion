// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"
#include "wallet.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
#include "base58.h"
#include "kernel.h"
#include "coincontrol.h" 
#include "smessage.h"
#include <boost/algorithm/string/replace.hpp>

using namespace std;
extern unsigned int nStakeMaxAge;

unsigned int nStakeSplitAge = 20 * 24 * 60 * 60;
int64_t nStakeCombineThreshold = 100 * COIN;


//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

struct CompareValueOnly
{
    bool operator()(const pair<int64_t, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<int64_t, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

CPubKey CWallet::GenerateNewKey()
{
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    RandAddSeedPerfmon();
    CKey key;
    key.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = key.GetPubKey();

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKey(key))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return key.GetPubKey();
}

bool CWallet::AddKey(const CKey& key)
{
    CPubKey pubkey = key.GetPubKey();

    if (!CCryptoKeyStore::AddKey(key))
        return false;
    if (!fFileBacked)
        return true;
    if (!IsCrypted())
        return CWalletDB(strWalletFile).WriteKey(pubkey, key.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]);
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

// optional setting to unlock wallet for staking only
// serves to disable the trivial sendmoney when OS account compromised
// provides no real security
bool fWalletUnlockStakingOnly = false;

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (!CCryptoKeyStore::Unlock(vMasterKey))
                return false;
            break;
        }
        UnlockStealthAddresses(vMasterKey);
        SecureMsgWalletUnlocked();
        return true;
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey)
                && UnlockStealthAddresses(vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                printf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();

                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion >= 40000)
        {
            // Versions prior to 0.4.0 did not support the "minversion" record.
            // Use a CCorruptAddress to make them crash instead.
            CCorruptAddress corruptAddress;
            pwalletdb->WriteSetting("addrIncoming", corruptAddress);
        }
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey(nDerivationMethodIndex);

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    printf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1); //We now probably have half of our keys encrypted in memory, and half not...die and let the user reload their unencrypted wallet.
        }

        std::set<CStealthAddress>::iterator it;
        for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
        {
            if (it->scan_secret.size() < 32) {
                continue; // stealth address is not owned
            }
            // -- CStealthAddress is only sorted on spend_pubkey
            CStealthAddress &sxAddr = const_cast<CStealthAddress&>(*it);
            
            if (fDebug) {
                printf("Encrypting stealth key %s\n", sxAddr.Encoded().c_str());
            }
            
            std::vector<unsigned char> vchCryptedSecret;
            
            CSecret vchSecret;
            vchSecret.resize(32);
            memcpy(&vchSecret[0], &sxAddr.spend_secret[0], 32);
            
            uint256 iv = Hash(sxAddr.spend_pubkey.begin(), sxAddr.spend_pubkey.end());
            if (!EncryptSecret(vMasterKey, vchSecret, iv, vchCryptedSecret)) {
                printf("Error: Failed encrypting stealth key %s\n", sxAddr.Encoded().c_str());
                continue;
            }
            
            sxAddr.spend_secret = vchCryptedSecret;
            pwalletdbEncryption->WriteStealthAddress(sxAddr);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
                exit(1); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

CWallet::TxItems CWallet::OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount)
{
    CWalletDB walletdb(strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-order multimap.
    TxItems txOrdered;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, (CAccountingEntry*)0)));
    }
    acentries.clear();
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
    }

    return txOrdered;
}

void CWallet::WalletUpdateSpent(const CTransaction &tx, bool fBlock)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (txin.prevout.n >= wtx.vout.size())
                    printf("WalletUpdateSpent: bad wtx %s\n", wtx.GetHash().ToString().c_str());
                else if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
                {
                    printf("WalletUpdateSpent found spent coin %s ONION %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkSpent(txin.prevout.n);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
                }
            }
        }

        if (fBlock)
        {
            uint256 hash = tx.GetHash();
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(hash);
            CWalletTx& wtx = (*mi).second;

            BOOST_FOREACH(const CTxOut& txout, tx.vout)
            {
                if (IsMine(txout))
                {
                    wtx.MarkUnspent(&txout - &tx.vout[0]);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, hash, CT_UPDATED);
                }
            }
        }

    }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (wtxIn.hashBlock != 0)
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    unsigned int latestNow = wtx.nTimeReceived;
                    unsigned int latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        std::list<CAccountingEntry> acentries;
                        TxItems txOrdered = OrderedTxItems(acentries);
                        for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    unsigned int& blocktime = mapBlockIndex[wtxIn.hashBlock]->nTime;
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    printf("AddToWallet() : found %s in block %s not in index\n",
                           wtxIn.GetHash().ToString().substr(0,10).c_str(),
                           wtxIn.hashBlock.ToString().c_str());
            }
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        //// debug print
        printf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().substr(0,10).c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        CScript scriptDefaultKey;
        scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if (txout.scriptPubKey == scriptDefaultKey)
            {
                CPubKey newDefaultKey;
                if (GetKeyFromPool(newDefaultKey, false))
                {
                    SetDefaultKey(newDefaultKey);
                    SetAddressBookName(vchDefaultKey.GetID(), "");
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx, (wtxIn.hashBlock != 0));

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
    uint256 hash = tx.GetHash();
    {
        LOCK(cs_wallet);
        bool fExisted = mapWallet.count(hash);
        if (fExisted && !fUpdate) {
            return false;
        }
        mapValue_t mapNarr;
        FindStealthTransactions(tx, mapNarr);

        if (fExisted || IsMine(tx) || IsFromMe(tx)) 
        {
            CWalletTx wtx(this,tx);
            if (!mapNarr.empty()) {
                wtx.mapValue.insert(mapNarr.begin(), mapNarr.end());
            }
            // Get merkle branch if transaction was found in a block
            if (pblock) {
                wtx.SetMerkleBranch(pblock);
            }
            return AddToWallet(wtx);
        }
        else {
            WalletUpdateSpent(tx);
        }
    }
    return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


bool CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return true;
        }
    }
    return false;
}

int64_t CWallet::GetDebit(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    CTxDestination address;

    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a TX_PUBKEYHASH that is mine but isn't in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (ExtractDestination(txout.scriptPubKey, address) && ::IsMine(*this, address))
    {
        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase() || IsCoinStake())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list<pair<CTxDestination, int64_t> >& listReceived,
                           list<pair<CTxDestination, int64_t> >& listSent, int64_t& nFee, string& strSentAccount) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    int64_t nDebit = GetDebit();
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        int64_t nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        // Skip special stake out
        if (txout.scriptPubKey.empty())
            continue;

        bool fIsMine;
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
            fIsMine = pwallet->IsMine(txout);
        }
        else if (!(fIsMine = pwallet->IsMine(txout)))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
        {
            printf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                   this->GetHash().ToString().c_str());
            address = CNoDestination();
        }

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(make_pair(address, txout.nValue));

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine)
            listReceived.push_back(make_pair(address, txout.nValue));
    }

}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64_t& nReceived,
                                  int64_t& nSent, int64_t& nFee) const
{
    nReceived = nSent = nFee = 0;

    int64_t allFee;
    string strSentAccount;
    list<pair<CTxDestination, int64_t> > listReceived;
    list<pair<CTxDestination, int64_t> > listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64_t)& s, listSent)
            nSent += s.second;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64_t)& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.first))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.first);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.second;
            }
            else if (strAccount.empty())
            {
                nReceived += r.second;
            }
        }
    }
}

void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        BOOST_FOREACH(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        // This critsect is OK because txdb is already open
        {
            LOCK(pwallet->cs_wallet);
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
                if (mi != pwallet->mapWallet.end())
                {
                    tx = (*mi).second;
                    BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (!fClient && txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                {
                    BOOST_FOREACH(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
                }
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            // no need to read and scan block, if block was created before
            // our wallet birthday (as adjusted for block time variability)
            if (nTimeFirstKey && (pindex->nTime < (nTimeFirstKey - 7200))) {
                pindex = pindex->pnext;
                continue;
            }

            CBlock block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
    return ret;
}

int CWallet::ScanForWalletTransaction(const uint256& hashTx)
{
    CTransaction tx;
    tx.ReadFromDisk(COutPoint(hashTx, 0));
    if (AddToWalletIfInvolvingMe(tx, NULL, true, true))
        return 1;
    return 0;
}

void CWallet::ReacceptWalletTransactions()
{
    CTxDB txdb("r");
    bool fRepeat = true;
    while (fRepeat)
    {
        LOCK(cs_wallet);
        fRepeat = false;
        vector<CDiskTxPos> vMissingTx;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if ((wtx.IsCoinBase() && wtx.IsSpent(0)) || (wtx.IsCoinStake() && wtx.IsSpent(1)))
                continue;

            CTxIndex txindex;
            bool fUpdated = false;
            if (txdb.ReadTxIndex(wtx.GetHash(), txindex))
            {
                // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
                if (txindex.vSpent.size() != wtx.vout.size())
                {
                    printf("ERROR: ReacceptWalletTransactions() : txindex.vSpent.size() %" PRIszu " != wtx.vout.size() %" PRIszu "\n", txindex.vSpent.size(), wtx.vout.size());
                    continue;
                }
                for (unsigned int i = 0; i < txindex.vSpent.size(); i++)
                {
                    if (wtx.IsSpent(i))
                        continue;
                    if (!txindex.vSpent[i].IsNull() && IsMine(wtx.vout[i]))
                    {
                        wtx.MarkSpent(i);
                        fUpdated = true;
                        vMissingTx.push_back(txindex.vSpent[i]);
                    }
                }
                if (fUpdated)
                {
                    printf("ReacceptWalletTransactions found spent coin %s ONION %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkDirty();
                    wtx.WriteToDisk();
                }
            }
            else
            {
                // Re-accept any txes of ours that aren't already in a block
                if (!(wtx.IsCoinBase() || wtx.IsCoinStake()))
                    wtx.AcceptWalletTransaction(txdb);
            }
        }
        if (!vMissingTx.empty())
        {
            // TODO: optimize this to scan just part of the block chain?
            if (ScanForWalletTransactions(pindexGenesisBlock))
                fRepeat = true;  // Found missing transactions: re-do re-accept.
        }
    }
}

void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
    {
        if (!(tx.IsCoinBase() || tx.IsCoinStake()))
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayTransaction((CTransaction)tx, hash);
        }
    }
    if (!(IsCoinBase() || IsCoinStake()))
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            printf("Relaying wtx %s\n", hash.ToString().substr(0,10).c_str());
            RelayTransaction((CTransaction)*this, hash);
        }
    }
}

void CWalletTx::RelayWalletTransaction()
{
   CTxDB txdb("r");
   RelayWalletTransaction(txdb);
}

void CWallet::ResendWalletTransactions(bool fForce)
{
    if (!fForce)
    {
        // Do this infrequently and randomly to avoid giving away
        // that these are our transactions.
        static int64_t nNextTime;
        if (GetTime() < nNextTime)
            return;
        bool fFirst = (nNextTime == 0);
        nNextTime = GetTime() + GetRand(30 * 60);
        if (fFirst)
            return;

        // Only do it if there's been a new block since last time
        static int64_t nLastTime;
        if (nTimeBestReceived < nLastTime)
            return;
        nLastTime = GetTime();
    }

    // Rebroadcast any of our txes that aren't in a block yet
    printf("ResendWalletTransactions()\n");
    CTxDB txdb("r");
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (fForce || nTimeBestReceived - (int64_t)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            if (wtx.CheckTransaction())
                wtx.RelayWalletTransaction(txdb);
            else
                printf("ResendWalletTransactions() : CheckTransaction failed for transaction %s\n", wtx.GetHash().ToString().c_str());
        }
    }
}






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64_t CWallet::GetBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

int64_t CWallet::GetUnconfirmedBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

int64_t CWallet::GetImmatureBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& pcoin = (*it).second;
            if (pcoin.IsCoinBase() && pcoin.GetBlocksToMaturity() > 0 && pcoin.IsInMainChain())
                nTotal += GetCredit(pcoin);
        }
    }
    return nTotal;
}

// populate vCoins with vector of spendable COutputs
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            if(pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
                if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue &&
                (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
                    vCoins.push_back(COutput(pcoin, i, nDepth));

        }
    }
}

void CWallet::AvailableCoinsMinConf(vector<COutput>& vCoins, int nConf) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if(pcoin->GetDepthInMainChain() < nConf)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
                if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue)
                    vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain()));
        }
    }
}

static void ApproximateBestSubset(vector<pair<int64, pair<const CWalletTx*,unsigned int> > >vValue, int64 nTotalLower, int64 nTargetValue,
                                  vector<char>& vfBest, int64& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

// DeepOnion: total coins staked (non-spendable until maturity)
int64_t CWallet::GetStake() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*pcoin);
    }
    return nTotal;
}

int64_t CWallet::GetNewMint() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*pcoin);
    }
    return nTotal;
}

bool CWallet::SelectCoinsMinConf(int64 nTargetValue, unsigned int nSpendTime, int nConfMine, int nConfTheirs, vector<COutput> vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<int64>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
    int64 nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;  

        int64 n = pcoin->vout[i].nValue;

        pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    int64 nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        if (fDebug && GetBoolArg("-printpriority"))
        {
            //// debug print
            printf("SelectCoins() best subset: ");
            for (unsigned int i = 0; i < vValue.size(); i++)
                if (vfBest[i])
                    printf("%s ", FormatMoney(vValue[i].first).c_str());
            printf("total %s\n", FormatMoney(nBest).c_str());
        }
    }

    return true;
}

bool CWallet::SelectCoins(int64 nTargetValue, unsigned int nSpendTime, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet, const CCoinControl* coinControl) const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected())
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 0, 1, vCoins, setCoinsRet, nValueRet));
}

// Select some coins without random shuffle or best subset approximation
bool CWallet::SelectCoinsSimple(int64_t nTargetValue, unsigned int nSpendTime, int nMinConf, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    vector<COutput> vCoins;
    AvailableCoinsMinConf(vCoins, nMinConf);

    setCoinsRet.clear();
    nValueRet = 0;

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;
        int i = output.i;

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue)
            break;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;

        int64_t n = pcoin->vout[i].nValue;

        pair<int64_t,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n >= nTargetValue)
        {
            // If input value is greater or equal to target then simply insert
            //    it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        }
        else if (n < nTargetValue + CENT)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
        }
    }

    return true;
}

bool CWallet::CreateTransaction(const vector<pair<CScript, int64_t> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, const CCoinControl* coinControl)
{
    int64 nValue = 0;
    BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
    {
        if (nValue < 0) {
	        printf("CreateTransaction() : nValue < 0 \n");
            return false;
	    }
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0) {
	    printf("CreateTransaction() : vecSend is empty or nValue < 0 \n");
        return false;
    }

    wtxNew.BindWallet(this);

    {
        LOCK2(cs_main, cs_wallet);
        // txdb must be opened before the mapWallet lock
		CTxDB txdb("r");
        {
            nFeeRet = nTransactionFee;
            while (true)
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                int64 nTotalValue = nValue + nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
                {
			        wtxNew.vout.push_back(CTxOut(s.second, s.first));
		        }
                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                int64 nValueIn = 0;
                if (!SelectCoins(nTotalValue, wtxNew.nTime, setCoins, nValueIn, coinControl))
                {
		            printf("CreateTransaction() : SelectCoins Failed \n");
                    return false;
		        }
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
                    dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain();
                }

                int64 nChange = nValueIn - nValue - nFeeRet;
                // if sub-cent change is required, the fee must be raised to at least Min Tx Fee
                // or until nChange becomes zero
                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < GetMinTxFee() && nChange > 0 && nChange < CENT)
                {
                    int64 nMoveToFee = min(nChange, GetMinTxFee() - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                // DeepOnion: sub-cent change is moved to fee
                if (nChange > 0 && nChange < MIN_TXOUT_AMOUNT)
                {
                    nFeeRet += nChange;
                    nChange = 0;
                }

                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;
                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                        scriptChange.SetDestination(coinControl->destChange);

                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey = reservekey.GetReservedKey();

                        scriptChange.SetDestination(vchPubKey.GetID());
                    }

                    // Insert change txn at random position:
                    vector<CTxOut>::iterator position = wtxNew.vout.begin() + GetRandInt(wtxNew.vout.size() + 1);
                    
                    // -- don't put change output between value and narration outputs
                    if (position > wtxNew.vout.begin() && position < wtxNew.vout.end())
                    {
                        while (position > wtxNew.vout.begin())
                        {
                            if (position->nValue != 0)
                                break;
                            position--;
                        };
                    };

                    wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

                // Sign
                int nIn = 0;
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    if (!SignSignature(*this, *coin.first, wtxNew, nIn++)) {
			            printf("CreateTransaction() : Sign Signature Failed \n");
                        return false;
		            }

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= MAX_BLOCK_SIZE_GEN/5) {
		                printf("CreateTransaction() : Transaction too large \n");
                        return false;
		            }
                dPriority /= nBytes;

                // Check that enough fee is included
                int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
                int64 nMinFee = wtxNew.GetMinFee(1, GMF_SEND, nBytes);

                if (nFeeRet < max(nPayFee, nMinFee))
                {
                    nFeeRet = max(nPayFee, nMinFee);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, const CCoinControl* coinControl)
{
    vector< pair<CScript, int64_t> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    
    if (sNarr.length() > 0)
    {
        std::vector<uint8_t> vNarr(sNarr.c_str(), sNarr.c_str() + sNarr.length());
        std::vector<uint8_t> vNDesc;
        
        vNDesc.resize(2);
        vNDesc[0] = 'n';
        vNDesc[1] = 'p';
        
        CScript scriptN = CScript() << OP_RETURN << vNDesc << OP_RETURN << vNarr;
        
        vecSend.push_back(make_pair(scriptN, 0));
    }
    
    // -- CreateTransaction won't place change between value and narr output.
    //    narration output will be for preceding output
    // -- narration will be added to mapValue later in FindStealthTransactions From CommitTransaction
    
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, coinControl);
}


// NovaCoin: get current stake weight
bool CWallet::GetStakeWeight(const CKeyStore& keystore, uint64_t& nMinWeight, uint64_t& nMaxWeight, uint64_t& nWeight)
{
    // Choose coins to use
    int64_t nBalance = GetBalance();

    if (nBalance <= nReserveBalance)
        return false;

    vector<const CWalletTx*> vwtxPrev;

    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;

    if (!SelectCoinsSimple(nBalance - nReserveBalance, GetTime(), nCoinbaseMaturity + 10, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    CTxDB txdb("r");
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        CTxIndex txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!txdb.ReadTxIndex(pcoin.first->GetHash(), txindex))
                continue;
        }

        int64_t nTimeWeight = GetWeight((int64_t)pcoin.first->nTime, (int64_t)GetTime());
        CBigNum bnCoinDayWeight = CBigNum(pcoin.first->vout[pcoin.second].nValue) * nTimeWeight / COIN / (24 * 60 * 60);

        // Weight is greater than zero
        if (nTimeWeight > 0)
        {
            nWeight += bnCoinDayWeight.getuint64();
        }

        // Weight is greater than zero, but the maximum value isn't reached yet
        if (nTimeWeight > 0 && nTimeWeight < nStakeMaxAge)
        {
            nMinWeight += bnCoinDayWeight.getuint64();
        }

        // Maximum weight was reached
        if (nTimeWeight == nStakeMaxAge)
        {
            nMaxWeight += bnCoinDayWeight.getuint64();
        }
    }

    return true;
}

bool CWallet::CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, int64_t nFees, CTransaction& txNew, CKey& key)
{
    CBlockIndex* pindexPrev = pindexBest;
    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    int64_t nBalance = GetBalance();

    if (nBalance <= nReserveBalance)
        return false;

    vector<const CWalletTx*> vwtxPrev;

    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;

    // Select coins with suitable depth
    if (!SelectCoinsSimple(nBalance - nReserveBalance, txNew.nTime, nCoinbaseMaturity + 10, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    int64_t nCredit = 0;
    CScript scriptPubKeyKernel;
    CTxDB txdb("r");
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        CTxIndex txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!txdb.ReadTxIndex(pcoin.first->GetHash(), txindex))
                continue;
        }

        // Read block header
        CBlock block;
        {
            LOCK2(cs_main, cs_wallet);
            if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                continue;
        }

        static int nMaxStakeSearchInterval = 60;
        if (block.GetBlockTime() + nStakeMinAge > txNew.nTime - nMaxStakeSearchInterval)
            continue; // only count coins meeting min age requirement

        bool fKernelFound = false;
        for (unsigned int n=0; n<min(nSearchInterval,(int64_t)nMaxStakeSearchInterval) && !fKernelFound && !fShutdown && pindexPrev == pindexBest; n++)
        {
            // Search backward in time from the given txNew timestamp 
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            uint256 hashProofOfStake = 0, targetProofOfStake = 0;
            COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
            if (CheckStakeKernelHash(nBits, block, txindex.pos.nTxPos - txindex.pos.nBlockPos, *pcoin.first, prevoutStake, txNew.nTime - n, hashProofOfStake, targetProofOfStake))
            {
                // Found a kernel
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : kernel found\n");
                vector<valtype> vSolutions;
                txnouttype whichType;
                CScript scriptPubKeyOut;
                scriptPubKeyKernel = pcoin.first->vout[pcoin.second].scriptPubKey;
                if (!Solver(scriptPubKeyKernel, whichType, vSolutions))
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : failed to parse kernel\n");
                    break;
                }
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : parsed kernel type=%d\n", whichType);
                if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH)
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : no support for kernel type=%d\n", whichType);
                    break;  // only support pay to public key and pay to address
                }
                if (whichType == TX_PUBKEYHASH) // pay to address type
                {
                    // convert to pay to public key type
                    if (!keystore.GetKey(uint160(vSolutions[0]), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }
                    scriptPubKeyOut << key.GetPubKey() << OP_CHECKSIG;
                }
                if (whichType == TX_PUBKEY)
                {
                    valtype& vchPubKey = vSolutions[0];
                    if (!keystore.GetKey(Hash160(vchPubKey), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }

                if (key.GetPubKey() != vchPubKey)
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : invalid key for kernel type=%d\n", whichType);
                        break; // keys mismatch
                    }

                    scriptPubKeyOut = scriptPubKeyKernel;
                }

                txNew.nTime -= n;
                txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
                nCredit += pcoin.first->vout[pcoin.second].nValue;
                vwtxPrev.push_back(pcoin.first);
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));

                if (GetWeight(block.GetBlockTime(), (int64_t)txNew.nTime) < nStakeSplitAge)
                    txNew.vout.push_back(CTxOut(0, scriptPubKeyOut)); //split stake
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : added kernel type=%d\n", whichType);
                fKernelFound = true;
                break;
            }
        }

        if (fKernelFound || fShutdown)
            break; // if kernel is found stop searching
    }

    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
        return false;

    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        // Attempt to add more inputs
        // Only add coins of the same key/address as kernel
        if (txNew.vout.size() == 2 && ((pcoin.first->vout[pcoin.second].scriptPubKey == scriptPubKeyKernel || pcoin.first->vout[pcoin.second].scriptPubKey == txNew.vout[1].scriptPubKey))
            && pcoin.first->GetHash() != txNew.vin[0].prevout.hash)
        {
            int64_t nTimeWeight = GetWeight((int64_t)pcoin.first->nTime, (int64_t)txNew.nTime);

            // Stop adding more inputs if already too many inputs
            if (txNew.vin.size() >= 100)
                break;
            // Stop adding more inputs if value is already pretty significant
            if (nCredit >= nStakeCombineThreshold)
                break;
            // Stop adding inputs if reached reserve limit
            if (nCredit + pcoin.first->vout[pcoin.second].nValue > nBalance - nReserveBalance)
                break;
            // Do not add additional significant input
            if (pcoin.first->vout[pcoin.second].nValue >= nStakeCombineThreshold)
                continue;
            // Do not add input that is still too young
            if (nTimeWeight < nStakeMinAge)
                continue;

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
            nCredit += pcoin.first->vout[pcoin.second].nValue;
            vwtxPrev.push_back(pcoin.first);
        }
    }

    // Calculate coin age reward
    {
        uint64_t nCoinAge;
        CTxDB txdb("r");
        if (!txNew.GetCoinAge(txdb, nCoinAge))
            return error("CreateCoinStake : failed to calculate coin age");

        int64_t nReward = GetProofOfStakeReward(nCoinAge, pindexBest);
        if (nReward <= 0)
            return false;

        nCredit += nReward;
    }

    // Set output amount
    if (txNew.vout.size() == 3)
    {
        txNew.vout[1].nValue = (nCredit / 2 / CENT) * CENT;
        txNew.vout[2].nValue = nCredit - txNew.vout[1].nValue;
    }
    else
        txNew.vout[1].nValue = nCredit;

    // Sign
    int nIn = 0;
    BOOST_FOREACH(const CWalletTx* pcoin, vwtxPrev)
    {
        if (!SignSignature(*this, *pcoin, txNew, nIn++))
            return error("CreateCoinStake : failed to sign coinstake");
    }

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
        return error("CreateCoinStake : exceeded coinstake size limit");

    // Successfully generated coinstake
    return true;
}


// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
    mapValue_t mapNarr;
    FindStealthTransactions(wtxNew, mapNarr);
    
    if (!mapNarr.empty())
    {
        BOOST_FOREACH(const PAIRTYPE(string,string)& item, mapNarr)
            wtxNew.mapValue[item.first] = item.second;
    };
    
    {
        LOCK2(cs_main, cs_wallet);
        printf("CommitTransaction:\n%s", wtxNew.ToString().c_str());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Mark old coins as spent
            set<CWalletTx*> setCoins;
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                coin.MarkSpent(txin.prevout.n);
                coin.WriteToDisk();
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Broadcast
        if (!wtxNew.AcceptToMemoryPool())
        {
            // This must not fail. The transaction has already been signed and recorded.
            printf("CommitTransaction() : Error: Transaction not valid\n");
            return false;
        }
        wtxNew.RelayWalletTransaction();
    }
    return true;
}


string CWallet::SendMoney(CScript scriptPubKey, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (fWalletUnlockStakingOnly)
    {
        string strError = _("Error: Wallet unlocked for block staking only, unable to create transaction.");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (!CreateTransaction(scriptPubKey, nValue, sNarr, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired, _("Sending...")))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}



string CWallet::SendMoneyToDestination(const CTxDestination& address, int64 nValue, std::string& sNarr, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    if (sNarr.length() > 24)
        return _("Narration must be 24 characters or less.");
    
    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, sNarr, wtxNew, fAskFee);
}


DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    NewThread(ThreadFlushWalletDB, &strWalletFile);
    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    bool fOwned;
    ChangeType nMode;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
        nMode = (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED;
        fOwned = ::IsMine(*this, address);
        
        mapAddressBook[address] = strName;
    }
    
    if (fOwned)
    {
        const CBitcoinAddress& caddress = address;
        SecureMsgWalletKeyChanged(caddress.ToString(), strName, nMode);
    }
    NotifyAddressBookChanged(this, address, strName, fOwned, nMode);
    
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        mapAddressBook.erase(address);
    }
    
    bool fOwned = ::IsMine(*this, address);
    string sName = "";
    if (fOwned)
    {
        const CBitcoinAddress& caddress = address;
        SecureMsgWalletKeyChanged(caddress.ToString(), sName, CT_DELETED);
    }
    NotifyAddressBookChanged(this, address, "", fOwned, CT_DELETED);

    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}


void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (block.IsProofOfWork() && mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %" PRId64 "", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
        }
        if (block.IsProofOfStake() && mapWallet.count(block.vtx[1].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[1].GetHash()];
            printf("    stake: %d  %d  %" PRId64 "", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
         }

    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64_t nKeys = max(GetArg("-keypool", 100), (int64_t)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %" PRId64 " new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int nSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (nSize > 0)
            nTargetSize = nSize;
        else
            nTargetSize = max(GetArg("-keypool", 100), (int64_t)0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            printf("keypool added key %" PRId64 ", size=%" PRIszu "\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        if (fDebug && GetBoolArg("-printkeypool"))
            printf("keypool reserve %" PRId64 "\n", nIndex);
    }
}

int64_t CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64_t nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    if(fDebug)
        printf("keypool keep %" PRId64 "\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    if(fDebug)
        printf("keypool return %" PRId64 "\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, int64_t> CWallet::GetAddressBalances()
{
    map<CTxDestination, int64_t> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                continue;

            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe() ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                int64_t n = pcoin->IsSpent(i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0 && IsMine(pcoin->vin[0]))
        {
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
            }

            // group change with input addresses
            BOOST_FOREACH(CTxOut txout, pcoin->vout)
                if (IsChange(txout))
                {
                    CWalletTx tx = mapWallet[pcoin->vin[0].prevout.hash];
                    CTxDestination txoutAddr;
                    if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                        continue;
                    grouping.insert(txoutAddr);
                }
            groupings.insert(grouping);
            grouping.clear();
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

// DeepOnion: check 'spent' consistency between wallet and txindex
// DeepOnion: fix wallet spent state according to txindex
void CWallet::FixSpentCoins(int& nMismatchFound, int64_t& nBalanceInQuestion, bool fCheckOnly)
{
    nMismatchFound = 0;
    nBalanceInQuestion = 0;

    LOCK(cs_wallet);
    vector<CWalletTx*> vCoins;
    vCoins.reserve(mapWallet.size());
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        vCoins.push_back(&(*it).second);

    CTxDB txdb("r");
    BOOST_FOREACH(CWalletTx* pcoin, vCoins)
    {
        // Find the corresponding transaction index
        CTxIndex txindex;
        if (!txdb.ReadTxIndex(pcoin->GetHash(), txindex))
            continue;
        for (unsigned int n=0; n < pcoin->vout.size(); n++)
        {
            if (IsMine(pcoin->vout[n]) && pcoin->IsSpent(n) && (txindex.vSpent.size() <= n || txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found lost coin %s ONION %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkUnspent(n);
                    pcoin->WriteToDisk();
                }
            }
            else if (IsMine(pcoin->vout[n]) && !pcoin->IsSpent(n) && (txindex.vSpent.size() > n && !txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found spent coin %s ONION %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkSpent(n);
                    pcoin->WriteToDisk();
                }
            }
        }
    }
}

// DeepOnion: disable transaction (only for coinstake)
void CWallet::DisableTransaction(const CTransaction &tx)
{
    if (!tx.IsCoinStake() || !IsFromMe(tx))
        return; // only disconnecting coinstake requires marking input unspent

    LOCK(cs_wallet);
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size() && IsMine(prev.vout[txin.prevout.n]))
            {
                prev.MarkUnspent(txin.prevout.n);
                prev.WriteToDisk();
            }
        }
    }
}

CPubKey CReserveKey::GetReservedKey()
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            printf("CReserveKey::GetReservedKey(): Warning: Using default key instead of a new key, top up your keypool!");
            vchPubKey = pwallet->vchDefaultKey;
        }
    }
    assert(vchPubKey.IsValid());
    return vchPubKey;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const {
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = FindBlockByHeight(std::max(0, nBestHeight - 144)); // the tip can be reorganised; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = (*it).second;
        std::map<uint256, CBlockIndex*>::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && blit->second->IsInMainChain()) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            BOOST_FOREACH(const CTxOut &txout, wtx.vout) {
                // iterate over all their outputs
                ::ExtractAffectedKeys(*this, txout.scriptPubKey, vAffected);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->nTime - 7200; // block times can be 2h off
}


string CWallet::GetConnectedIP(string key)
{
	map<string, string>::iterator it = mapAnonymousServices.find(key);

	if(it != mapAnonymousServices.end())
		return it->second;

	return "";
}



CNode* CWallet::GetConnectedNode(std::string ipAddress)
{
	CNode* pNodeFound = NULL;
	{
		LOCK(cs_vNodes);
		BOOST_FOREACH(CNode* pnode, vNodes)
		{
			string nodeAddr = pnode->addrName;
			nodeAddr = nodeAddr.substr(0, nodeAddr.find(":"));
			if(ipAddress == nodeAddr)
			{
				pNodeFound = pnode;
				break;
			}
		}
	}

	return pNodeFound;
}


std::string CWallet::ListCurrentServiceNodes()
{
	std::string str = "";
	int sz = mapAnonymousServices.size();
	if(sz == 0)
	{
		str = "No connected service nodes.\n";
		return str;
	}

	str += "Currently Connected Service Nodes:\n\n";
	for(map<string, string>::iterator it = mapAnonymousServices.begin(); it != mapAnonymousServices.end(); it++)
	{
		str += it->second + "\n";
	}

	str += "\n";
	return str;
}


bool CWallet::SelectAnonymousServiceMixNode(CNode*& pMixerNode, string& keyMixer, int cnt)
{
	int count = 0;
	int sz = mapAnonymousServices.size();
	if(sz < 2)
	{
		printf(">> ERROR. SelectAnonymousServiceMixNode: Not enough service nodes. Expected: at least 2. Real Size = %d\n", sz);
		return false;
	}

	srand(time(NULL) + 100 * cnt);
	int selected = rand() % sz;
	string selectedKey = "";
	string selectedIp = "";

	for(map<string, string>::iterator it = mapAnonymousServices.begin(); it != mapAnonymousServices.end(); it++)
	{
		if(cnt == selected)
		{
			selectedKey = it->first;
			selectedIp = it->second;
			break;
		}
		else
			++cnt;
	}
	pMixerNode = GetConnectedNode(selectedIp);

	while(pMixerNode == NULL)
	{
		if(++count > 3)
			break;

		sz = GetUpdatedServiceListCount();
		if(sz < 2)
		{
			printf(">> ERROR. SelectAnonymousServiceMixNode: Not enough service nodes. Expected: at least 2. Real Size After Update = %d\n", sz);
			return false;
		}

		selected = rand() % sz;
		for(map<string, string>::iterator it = mapAnonymousServices.begin(); it != mapAnonymousServices.end(); it++)
		{
			if(cnt == selected)
			{
				selectedKey = it->first;
				selectedIp = it->second;
				break;
			}
			else
				++cnt;
		}

		pMixerNode = GetConnectedNode(selectedIp);
	}
				
	if(pMixerNode == NULL)
	{
		printf(">> ERROR. SelectAnonymousServiceMixNode: Can not get Mixer Node.\n");
		return false;
	}
	else 
	{
		if(fDebugAnon)
			printf(">> Selected mixer ip = %s.\nSelected mixer key = %s\n", selectedIp.c_str(), selectedKey.c_str());
	}

	keyMixer = selectedKey;

	return true;
}


bool CWallet::FindGuarantorKey(map<string, string> mapSnList, std::string& guarantorKey)
{
	std::vector<std::string> matched;
	guarantorKey = "";

	for(map<string, string>::iterator it1 = mapAnonymousServices.begin(); it1 != mapAnonymousServices.end(); it1++)
	{
		for(map<string, string>::iterator it2 = mapSnList.begin(); it2 != mapSnList.end(); it2++)
		{
			if(it1->first == it2->first)
				matched.push_back(it1->first);
		}
	}

	int sz = matched.size();
	if(sz == 0)
	{
		return false;
	}

	if(sz == 1)
	{
		guarantorKey = matched.at(0);
		return true;
	}

	srand(time(NULL));
	int selected = rand() % sz;
	guarantorKey = matched.at(selected);
	return true;
}


bool CWallet::IsCurrentAnonymousTxInProcess()
{
	bool b = pCurrentAnonymousTxInfo->IsCurrentTxInProcess();
	if(b)
	{
		if(pCurrentAnonymousTxInfo->CanReset())
		{
			pCurrentAnonymousTxInfo->clean(false);
			b = false;
		}
	}
	return b;
}


bool CWallet::StartP2pMixerSendProcess(vector< pair<string, int64_t> > vecSendInfo, const CCoinControl *coinControl)
{
	CNode* pMixerNode = NULL;
	std::string keyMixer = "";
	std::string ipMixer = "";
	std::string anonymousTxId = "";
	std::string selfAddress = "";
	bool b = false;

	{
		LOCK(cs_deepsend);
		if(IsCurrentAnonymousTxInProcess())
		{
			printf(">> ERROR another active anonymous tx is in progress.\n");
			return false;
		}
		pCurrentAnonymousTxInfo->clean(true);

		// first find a mixer
		b = SelectAnonymousServiceMixNode(pMixerNode, keyMixer, 0);
		if(!b)
		{
			printf(">> ERROR in obtaining Mixer Node.\n");
			return false;
		}

		// now save send info
		pCurrentAnonymousTxInfo->SetInitialData(ROLE_SENDER, vecSendInfo, coinControl, NULL, pMixerNode, NULL, this);

		// send check-availability message 1st
		anonymousTxId = pCurrentAnonymousTxInfo->GetAnonymousId();
		selfAddress = pCurrentAnonymousTxInfo->GetSelfAddress();
	}
		
	int64_t baseAmount = 0;
	for(int i = 0; i < vecSendInfo.size(); i++)
		baseAmount += vecSendInfo.at(i).second;

	std::vector<unsigned char> vchSig;
	b = SignMessageUsingAddress(selfAddress, selfAddress, vchSig);
	if(!b) 
	{
		printf(">> StartP2pMixerSendProcess. ERROR can't sign the selfAddress message.\n");
		return false;
	}

	int cnt = 1;
	pMixerNode->PushMessage("asvcavail", anonymousTxId, selfAddress, mapAnonymousServices, baseAmount, cnt, vchSig);

	return true;
}

bool CWallet::DepositToMultisig(std::string& txid)
{
	txid = "";
	const CCoinControl* coinControl = NULL;

	if(pCurrentAnonymousTxInfo->GetAtxStatus() < ATX_STATUS_MSADDR)
	{
		return false;
	}

	coinControl = pCurrentAnonymousTxInfo->GetCoinControl();

    int64_t nBalance = 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);
		
    BOOST_FOREACH(const COutput& out, vCoins)
        nBalance += out.tx->vout[out.i].nValue;

	if(nBalance == 0)
	{
		coinControl = NULL;
		AvailableCoins(vCoins, true, coinControl);
		BOOST_FOREACH(const COutput& out, vCoins)
			nBalance += out.tx->vout[out.i].nValue;
	}

	int64_t requiredAmount = pCurrentAnonymousTxInfo->GetTotalRequiredCoinsToSend();
	std::string multisigAddress = pCurrentAnonymousTxInfo->GetMultiSigAddress();

    if(requiredAmount > nBalance)
    {
        return false;
    }

    {
        LOCK2(cs_main, cs_wallet);

		std::vector<std::pair<CScript, int64_t> > vecSend;
		CScript scriptPubKey;
		scriptPubKey.SetDestination(CBitcoinAddress(multisigAddress).Get());
		vecSend.push_back(make_pair(scriptPubKey, requiredAmount));

        CWalletTx wtx;
        CReserveKey keyChange(this);
        int64_t nFeeRequired = 0;
        bool fCreated = CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, coinControl);

        if(!fCreated)
        {
            if((requiredAmount + nFeeRequired) > nBalance) 
            {
                return false;
            }

            return false;
        }

        if(!CommitTransaction(wtx, keyChange))
        {
            return false;
        }
        txid = wtx.GetHash().GetHex();
    }

	return true;
}


bool CWallet::SendCoinsToDestination(std::string& txid)
{
	txid = "";
	const CCoinControl* coinControl = NULL;

    int64_t nBalance = 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);
    BOOST_FOREACH(const COutput& out, vCoins)
        nBalance += out.tx->vout[out.i].nValue;

	int64_t requiredAmount = pCurrentAnonymousTxInfo->GetTotalRequiredCoinsToSend();
    if(requiredAmount > nBalance)
    {
        return false;
    }

    {
        LOCK2(cs_main, cs_wallet);

		std::vector<std::pair<CScript, int64_t> > vecSend;
		CScript scriptPubKey;
		int sz = pCurrentAnonymousTxInfo->GetSize();

		for(int i = 0; i < sz; i++)
		{
			std::pair<std::string, int64_t> senddata = pCurrentAnonymousTxInfo->GetValue(i);
			scriptPubKey.SetDestination(CBitcoinAddress(senddata.first).Get());
			vecSend.push_back(make_pair(scriptPubKey, senddata.second));
		}

        CWalletTx wtx;
        CReserveKey keyChange(this);
        int64_t nFeeRequired = 0;
        bool fCreated = CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, coinControl);

        if(!fCreated)
        {
            if((requiredAmount + nFeeRequired) > nBalance) 
            {
                return false;
            }

            return false;
        }

        if(!CommitTransaction(wtx, keyChange))
        {
			// need revert back
            return false;
        }
        txid = wtx.GetHash().GetHex();
    }

	pCurrentAnonymousTxInfo->SetSendTx(txid);
	return true;
}


bool CWallet::GetAnonymousSend(const CCoinControl *coinControl)
{
	bool b = false;
	if(coinControl != NULL)
		b = coinControl->GetAnonymousSend();

	return b;
}


bool CWallet::SignMessageUsingAddress(std::string message, std::string address, std::vector<unsigned char>& vchSig)
{
	CBitcoinAddress addr(address);
    if (!addr.IsValid())
	{
    	if(fDebugAnon)
    		printf(">> Address is invalid\n");
    	
		return false;
	}

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
	{
    	if(fDebugAnon)
    		printf(">> Can't get address key id\n");

    	return false;
	}

    CKey key;
    if (!GetKey(keyID, key))
	{
    	if(fDebugAnon)
    		printf(">> Can't get address key\n");

    	return false;
	}

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << message;

    if (!key.SignCompact(Hash(ss.begin(), ss.end()), vchSig))
	{
    	if(fDebugAnon)
    		printf(">> Key SignCompact error.\n");

    	return false;
	}

    return true;
}


bool CWallet::VerifyMessageSignature(std::string message, std::string address, std::vector<unsigned char> vchSig)
{
    CBitcoinAddress addr(address);
    if (!addr.IsValid())
	{
		return false;
	}

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
	{
		return false;
	}

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << message;

    CKey key;
    if (!key.SetCompactSignature(Hash(ss.begin(), ss.end()), vchSig))
	{
        return false;
	}

    return (key.GetPubKey().GetID() == keyID);
}


static const int MAX_ALLOWED_ASLIST_SIZE = 32;

void CWallet::UpdateAnonymousServiceList(CNode* pNode, std::string keyAddress, std::string status)
{
	bool bAdd = false;
	if(status == "true")
		bAdd = true;

	int sz = mapAnonymousServices.size();

	// max MAX_ALLOWED_ASLIST_SIZE nodes on the list, if over, clean up the old list
	if(bAdd && sz > MAX_ALLOWED_ASLIST_SIZE)
	{
		sz = GetUpdatedServiceListCount();
		if(sz > MAX_ALLOWED_ASLIST_SIZE)
			return;
	}

	string addrName = pNode->addrName;
	string addr = addrName.substr(0, addrName.find(":"));
	// printf(">> addrName = %s\n", addrName.c_str());
	// printf(">> addr = %s\n", addr.c_str());	

	// remove ipv6 address
	string ipv6 = "[";
	if(addr.find(ipv6) != std::string::npos)
		return;
	
	// remove non-onion address
	string onion = ".onion";
	if(addr.find(onion) == std::string::npos)
		return;

	if(fDebugAnon)
		printf(">> UpdateAnonymousServiceList. key = %s, addr = %s, status = %s\n", keyAddress.c_str(), addr.c_str(), status.c_str());
	
	{
		LOCK(cs_servicelist);
		std::map<std::string, std::string>::iterator it = mapAnonymousServices.find(keyAddress);
		if(bAdd)
		{
			if(it == mapAnonymousServices.end())
			{
				CNode* pN = GetConnectedNode(addr);
				if(pN == NULL)
				{
					LOCK(cs_vNodes);
					vNodes.push_back(pNode);
				}
				
				if(pN == NULL) {
					bool b1 = CheckAnonymousServiceConditions();
					if(b1 && selfAddress != "")
						pNode->PushMessage("mixservice", selfAddress, string("true"));
				}
				
				mapAnonymousServices.insert(make_pair(keyAddress, addr));
			}
			else	// already exist
			{
				if(addr != it->second)
				{
					mapAnonymousServices.erase(it);
					CNode* pN = GetConnectedNode(addr);
					if(pN == NULL)
					{
						LOCK(cs_vNodes);
						vNodes.push_back(pNode);
					}

					mapAnonymousServices.insert(make_pair(keyAddress, addr));
				}
			}
		}
		else
		{
			if(it != mapAnonymousServices.end())
				mapAnonymousServices.erase(it);
		}
	}
}


int CWallet::GetUpdatedServiceListCount()
{
	int sz = mapAnonymousServices.size();
	if(fDebugAnon)
		printf(">> GetUpdatedServiceListCount: init sz = %d\n", sz);

	map<string, string> mapNew;
	{
		LOCK2(cs_servicelist, cs_vNodes);
		bool exist = false;
		for(map<string, string>::iterator it = mapAnonymousServices.begin(); it != mapAnonymousServices.end(); it++)
		{
			std::string ip = it->second;
			exist = false;

			BOOST_FOREACH(CNode* pnode, vNodes)
			{
				string nodeAddr = pnode->addrName;
				nodeAddr = nodeAddr.substr(0, nodeAddr.find(":"));
				if(ip == nodeAddr)
				{
					exist = true;
					break;
				}
			}
			
			if(exist == true)
			{
				mapNew.insert(make_pair(it->first, it->second));
			}
		}
	}

	mapAnonymousServices = mapNew;
	sz = mapAnonymousServices.size();
	if(fDebugAnon)
		printf(">> GetUpdatedServiceListCount: after sz = %d\n", sz);

	return sz;
}


bool CWallet::CheckAnonymousServiceConditions() 
{
    int64_t nBalance = 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins);

    BOOST_FOREACH(const COutput& out, vCoins)
        nBalance += out.tx->vout[out.i].nValue;

	if(nBalance < MIN_ANON_SERVICE_COIN)
		return false;

	if(GetSelfAddressCount() > 1)
		return true;
	
	return false;
}


std::string CWallet::GetAddressPubKey(std::string strAddress)
{
	CBitcoinAddress address(strAddress);
    bool isValid = address.IsValid();

	if(!isValid)
	{
		if(fDebugAnon)
			printf(">> ERROR. CWallet::GetAddressPubKey: invalid address.\n");
		return "";
	}

	CTxDestination dest = address.Get();
    bool fMine = ::IsMine(*this, dest);
	if(!fMine)
	{
		if(fDebugAnon)
			printf(">> ERROR. CWallet::GetAddressPubKey: address is not mine.\n");
		return "";
	}

	CKeyID keyID = boost::get<CKeyID>(dest);
    CPubKey vchPubKey;
    GetPubKey(keyID, vchPubKey);
    std::string pubKey = HexStr(vchPubKey.Raw());
	return pubKey;
}


bool CWallet::CreateMultiSigAddress()
{
	// Get data from pCurrentAnonymousTxInfo
	int nRequired = 2;
	std::vector<std::string> keys = pCurrentAnonymousTxInfo->GetAllPubKeys();

    // Construct using pay-to-script-hash:
    std::vector<CKey> pubkeys;
    pubkeys.resize(keys.size());

	for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys.at(i);
		if(fDebugAnon)
			printf(">> Public Key: %s\n", ks.c_str());

		// Case 1: Bitcoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
			{
                printf("CreateMultiSigAddress(): %s does not refer to a key\n", ks.c_str());
				return false;
			}

            CPubKey vchPubKey;
            if (!GetPubKey(keyID, vchPubKey))
			{
                printf("CreateMultiSigAddress(): no full public key for address %s\n", ks.c_str());
				return false;
			}
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
			{
                printf("CreateMultiSigAddress(): Invalid public key: %s\n", ks.c_str());
				return false;
			}
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
			{
                printf("CreateMultiSigAddress(): Invalid public key: %s\n", ks.c_str());
				return false;
			}
        }
        else
        {
            printf("CreateMultiSigAddress(): Invalid public key: %s\n", ks.c_str());
			return false;
        }
    }

    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);
    CScriptID innerID = inner.GetID();
    CBitcoinAddress address(innerID);

	// add results to pCurrentAnonymousTxInfo
    std::string multiSigAddress = address.ToString();
    std::string redeemScript = HexStr(inner.begin(), inner.end());
	if(fDebugAnon)
		printf(">> CreateMultiSigAddress: multiSigAddress = %s, redeemScript = %s\n",
			multiSigAddress.c_str(), redeemScript.c_str());

	pCurrentAnonymousTxInfo->SetMultiSigAddress(multiSigAddress, redeemScript);
	return true;
}


bool CWallet::ExtractVoutAndScriptPubKey(AnonymousTxRole role, std::string txid, int& voutn, std::string& hexScriptPubKey)
{
	if(fDebug)
		printf(">> ExtractVoutAndScriptPubKey for txid = %s\n", txid.c_str());

    uint256 hash;
    hash.SetHex(txid);
    CTransaction tx;
    uint256 hashBlock = 0;
    if(!::GetTransaction(hash, tx, hashBlock))
	{
        printf(">> ExtractVoutAndScriptPubKey for txid = %s can not be found.\n", txid.c_str());
		return false;
	}

	int64_t amount = pCurrentAnonymousTxInfo->GetTotalRequiredCoinsToSend(role);
	std::vector<CTxOut> vout = tx.vout;
	int sz = vout.size();
	voutn = 0;
	if(sz > 0)
	{
		for(int i = 0; i < sz; i++)
		{
			if(vout.at(i).nValue == amount)
			{
				voutn = i;
				break;
			}
		}
	}	

	CScript scriptPubKey = tx.vout[voutn].scriptPubKey;
	hexScriptPubKey = HexStr(scriptPubKey.begin(), scriptPubKey.end());
	return true;
}


std::string CWallet::CreateMultiSigDistributionTx()
{
	// extract info from deposit tx's
	// sender
	std::string txidSender = pCurrentAnonymousTxInfo->GetTxid(ROLE_SENDER);
	int voutnSender;
	string scriptPubKeySender;
	bool b = ExtractVoutAndScriptPubKey(ROLE_SENDER, txidSender, voutnSender, scriptPubKeySender);
	if(!b)
	{
		printf("ERROR. Can not extract sender's deposit tx voutN and scriptPubKey.\n");
		return "";
	}
	pCurrentAnonymousTxInfo->SetVoutAndScriptPubKey(ROLE_SENDER, voutnSender, scriptPubKeySender);

	// mixer
	std::string txidMixer = pCurrentAnonymousTxInfo->GetTxid(ROLE_MIXER);
	int voutnMixer;
	string scriptPubKeyMixer;
	b = ExtractVoutAndScriptPubKey(ROLE_MIXER, txidMixer, voutnMixer, scriptPubKeyMixer);
	if(!b)
	{
		printf("ERROR. Can not extract mixer's deposit tx voutN and scriptPubKey.\n");
		return "";
	}
	pCurrentAnonymousTxInfo->SetVoutAndScriptPubKey(ROLE_MIXER, voutnMixer, scriptPubKeyMixer);

	// guarantor
	std::string txidGuarantor = pCurrentAnonymousTxInfo->GetTxid(ROLE_GUARANTOR);
	int voutnGuarantor;
	string scriptPubKeyGuarantor;
	b = ExtractVoutAndScriptPubKey(ROLE_GUARANTOR, txidGuarantor, voutnGuarantor, scriptPubKeyGuarantor);
	if(!b)
	{
		printf("ERROR. Can not extract guarantor's deposit tx voutN and scriptPubKey.\n");
		return "";
	}
	pCurrentAnonymousTxInfo->SetVoutAndScriptPubKey(ROLE_GUARANTOR, voutnGuarantor, scriptPubKeyGuarantor);

	// now creating raw distribution tx
    CTransaction rawTx;

    uint256 txid256;
    txid256.SetHex(txidSender);
    CTxIn in1(COutPoint(uint256(txid256), voutnSender));
    rawTx.vin.push_back(in1);

    txid256.SetHex(txidMixer);
    CTxIn in2(COutPoint(uint256(txid256), voutnMixer));
    rawTx.vin.push_back(in2);

    txid256.SetHex(txidGuarantor);
    CTxIn in3(COutPoint(uint256(txid256), voutnGuarantor));
    rawTx.vin.push_back(in3);

    set<CBitcoinAddress> setAddress;
	int64_t baseAmount = pCurrentAnonymousTxInfo->GetTotalRequiredCoinsToSend(ROLE_MIXER);
	int64_t paidfee = baseAmount * DEEPSEND_FEE_RATE;
	if(paidfee < DEEPSEND_MIN_FEE)
		paidfee = DEEPSEND_MIN_FEE;
	int64_t fee = 5 * MIN_TX_FEE;	// may need to adjust this
	int64_t servicefee = (paidfee - fee) / 2;

	// sender gets baseAmount
	std::string addressSender = pCurrentAnonymousTxInfo->GetAddress(ROLE_SENDER);
    CBitcoinAddress addressS(addressSender);
    setAddress.insert(addressS);
    CScript spkSender;
    spkSender.SetDestination(addressS.Get());
	CTxOut out1(baseAmount, spkSender);
    rawTx.vout.push_back(out1);

	// mixer gets 2 * baseAmount + servicefee
	std::string addressMixer = pCurrentAnonymousTxInfo->GetAddress(ROLE_MIXER);
    CBitcoinAddress addressM(addressMixer);
    setAddress.insert(addressM);
    CScript spkMixer;
	spkMixer.SetDestination(addressM.Get());
	CTxOut out2(2 * baseAmount + servicefee, spkMixer);
    rawTx.vout.push_back(out2);

	// guarantor gets baseAmount + servicefee
	std::string addressGuarantor = pCurrentAnonymousTxInfo->GetAddress(ROLE_GUARANTOR);
    CBitcoinAddress addressG(addressGuarantor);
    setAddress.insert(addressG);
    CScript spkGuarantor;
	spkGuarantor.SetDestination(addressG.Get());
	CTxOut out3(baseAmount + servicefee, spkGuarantor);
    rawTx.vout.push_back(out3);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;
    std::string tx = HexStr(ss.begin(), ss.end());
	if(fDebugAnon)
		printf(">> Distribution tx created. tx = %s\n", tx.c_str());

	pCurrentAnonymousTxInfo->SetTx(tx, 0);

	return tx;
}


bool CWallet::GetPrivKey(std::string strAddress, std::string& strPrivateKey)
{
	strPrivateKey = "";
    CBitcoinAddress address;
    if(!address.SetString(strAddress))
	{
		printf("ERROR. GetPrivKey: Invalid SuperCoin address.\n");
        return false;
	}

    CKeyID keyID;
    if(!address.GetKeyID(keyID))
	{
		printf("ERROR. GetPrivKey: Address does not refer to a key.\n");
        return false;
	}

    CSecret vchSecret;
    bool fCompressed;
    if(!GetSecret(keyID, vchSecret, fCompressed))
	{
		printf("ERROR. GetPrivKey: Private key for address %s is not known.\n", strAddress.c_str());
        return false;
	}

    strPrivateKey = CBitcoinSecret(vchSecret, fCompressed).ToString();
	return true;
}


bool CWallet::AddPrevTxOut(AnonymousTxRole role, CBasicKeyStore& tempKeystore, std::map<COutPoint, CScript>& mapPrevOut)
{
	std::string txidHex = "";
	int nOut = 0;
	std::string pkHex = "";
	pCurrentAnonymousTxInfo->GetMultisigTxOutInfo(role, txidHex, nOut, pkHex);

	if(fDebugAnon)
	{
		printf(">> AddPrevTxOut: role = %d, txidHex = %s, nOut = %d, pkHex = %s\n", 
			role, txidHex.c_str(), nOut, pkHex.c_str());
	}

	std::string rdmScript = pCurrentAnonymousTxInfo->GetRedeemScript();
	if(fDebugAnon)
	{
		printf(">> AddPrevTxOut: rdmScript = %s\n", rdmScript.c_str());
	}

	uint256 txid;
    txid.SetHex(txidHex);

    vector<unsigned char> pkData(ParseHex(pkHex));
    CScript scriptPubKey(pkData.begin(), pkData.end());

    COutPoint outpoint(txid, nOut);
    if(mapPrevOut.count(outpoint))
    {
		// Complain if scriptPubKey doesn't match
		if (mapPrevOut[outpoint] != scriptPubKey)
		{
			string err("Previous output scriptPubKey mismatch:\n");
			err = err + mapPrevOut[outpoint].ToString() + "\nvs:\n"+
				scriptPubKey.ToString();
			printf("AddPrevTxOut: Error. %s\n", err.c_str());
			return false;
		}
	}
	else
		mapPrevOut[outpoint] = scriptPubKey;

	// if redeemScript given and not using the local wallet (private keys
	// given), add redeemScript to the tempKeystore so it can be signed:
	if (scriptPubKey.IsPayToScriptHash())
	{
		vector<unsigned char> rsData(ParseHex(rdmScript));
		CScript redeemScript(rsData.begin(), rsData.end());
		tempKeystore.AddCScript(redeemScript);
	}

	return true;
}


bool CWallet::SignMultiSigDistributionTx()
{
	std::string miltisigtx = pCurrentAnonymousTxInfo->GetTx();
	if(fDebugAnon)
		printf(">> SignMultiSigDistributionTx: miltisigtx = %s\n", miltisigtx.c_str());

	vector<unsigned char> txData(ParseHex(miltisigtx));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CTransaction> txVariants;
    while (!ssData.empty())
    {
        try 
		{
            CTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);

			if(fDebugAnon)
			{
				printf(">> SignMultiSigDistributionTx: CTransaction:\n");
				tx.print();
			}
        }
        catch (std::exception &e) 
		{
			printf("ERROR. SignMultiSigDistributionTx: TX decode failed.\n");
            return false;
        }
    }

    if (txVariants.empty())
	{
 		printf("ERROR. SignMultiSigDistributionTx: Missing transaction.\n");
        return false;
	}

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs):
    map<COutPoint, CScript> mapPrevOut;
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTransaction tempTx;
        MapPrevTx mapPrevTx;
        CTxDB txdb("r");
        map<uint256, CTxIndex> unused;
        bool fInvalid;

        // FetchInputs aborts on failure, so we go one at a time.
        tempTx.vin.push_back(mergedTx.vin[i]);
        tempTx.FetchInputs(txdb, unused, false, false, mapPrevTx, fInvalid);

        // Copy results into mapPrevOut:
        BOOST_FOREACH(const CTxIn& txin, tempTx.vin)
        {
            const uint256& prevHash = txin.prevout.hash;
            if (mapPrevTx.count(prevHash) && mapPrevTx[prevHash].second.vout.size()>txin.prevout.n)
                mapPrevOut[txin.prevout] = mapPrevTx[prevHash].second.vout[txin.prevout.n].scriptPubKey;
        }
    }

	// get self private key 
	std::string selfAddress = pCurrentAnonymousTxInfo->GetSelfAddress();
	std::string strPrivKey = "";
	bool b = GetPrivKey(selfAddress, strPrivKey);
	if(!b)
	{
		printf("SignMultiSigDistributionTx: failed to get private key, for selfAddress = %s\n", selfAddress.c_str());
		return false;
	}

	if(fDebugAnon)
		printf(">> SignMultiSigDistributionTx: selfAddress = %s, strPrivKey = %s...\n", selfAddress.c_str(), strPrivKey.substr(0,10).c_str());

    bool fGivenKeys = true;
    CBasicKeyStore tempKeystore;
    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strPrivKey);
    if(!fGood)
	{
 		printf("ERROR. SignMultiSigDistributionTx: Invalid private key. strPrivKey = %s\n", strPrivKey.c_str());
        return false;
	}
            
	CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    tempKeystore.AddKey(key);

    // Add previous txouts
	b = AddPrevTxOut(ROLE_SENDER,		tempKeystore, mapPrevOut);
	if(!b)
	{
		printf("SignMultiSigDistributionTx: failed add previous txout, for sender\n");
		return false;
	}

	b = AddPrevTxOut(ROLE_MIXER,		tempKeystore, mapPrevOut);
	if(!b)
	{
		printf("SignMultiSigDistributionTx: failed add previous txout, for mixer\n");
		return false;
	}

	b = AddPrevTxOut(ROLE_GUARANTOR,	tempKeystore, mapPrevOut);
	if(!b)
	{
		printf("SignMultiSigDistributionTx: failed add previous txout, for guarantor\n");
		return false;
	}

    const CKeyStore& keystore = tempKeystore;

    int nHashType = SIGHASH_ALL;
    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn& txin = mergedTx.vin[i];
        if (mapPrevOut.count(txin.prevout) == 0)
        {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = mapPrevOut[txin.prevout];

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
		{
            ::SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);
		}

        // ... and merge in other signatures:
        BOOST_FOREACH(const CTransaction& txv, txVariants)
        {
            txin.scriptSig = ::CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!::VerifyScript(txin.scriptSig, prevPubKey, mergedTx, i, 0))
            fComplete = false;
    }

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mergedTx;
	std::string signedTx = HexStr(ssTx.begin(), ssTx.end());

	int signedcount = pCurrentAnonymousTxInfo->GetSignedCount();
	if(fDebugAnon)
		printf(">> SignMultiSigDistributionTx: SignedCount before incrementing = %d\n", signedcount);

	++signedcount;

	if(fDebugAnon)
	{
		printf(">> SignMultiSigDistributionTx: signedTx = %s\n", signedTx.c_str());
		printf(">> SignMultiSigDistributionTx: SignedCount = %d\n", signedcount);
	}

	if(signedcount == 2 && fComplete == false)
	{
		printf("ERROR. SignMultiSigDistributionTx: signedcount == 2 but not complete.\n");
		return false;
	}
	else if(signedcount == 1 && fComplete == true)
	{
		printf("ERROR. SignMultiSigDistributionTx: signedcount == 1 but already complete.\n");
		return false;
	}

	pCurrentAnonymousTxInfo->SetTx(signedTx, signedcount);
	return true;
}


bool CWallet::SendMultiSigDistributionTx()
{
	std::string signedTx = pCurrentAnonymousTxInfo->GetTx();
	int signedCount = pCurrentAnonymousTxInfo->GetSignedCount();
	if(signedCount < 2)
	{
		printf("ERROR. SendMultiSigDistributionTx: there are not enough signings in the tx.\n");
		return false;
	}

    vector<unsigned char> txData(ParseHex(signedTx));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;

    // deserialize binary data stream
    try 
	{
        ssData >> tx;
    }
    catch (std::exception &e) 
	{
		printf("ERROR. SendMultiSigDistributionTx: TX decode failed.\n");
		return false;
    }

    uint256 hashTx = tx.GetHash();

    // See if the transaction is already in a block
    // or in the memory pool:
    CTransaction existingTx;
    uint256 hashBlock = 0;
    if(::GetTransaction(hashTx, existingTx, hashBlock))
    {
        if(hashBlock != 0)
		{
			printf("ERROR. SendMultiSigDistributionTx: Transaction already in block.\n");
			return false;
		}
    }
    else
    {
        // push to local node
        CTxDB txdb("r");
        if(!tx.AcceptToMemoryPool(txdb))
		{
			printf("ERROR. SendMultiSigDistributionTx: TX rejected.\n");
			return false;
		}

        SyncWithWallets(tx, NULL, true);
    }

    RelayTransaction(tx, hashTx);
    std::string committed = hashTx.GetHex();
	if(fDebugAnon)
		printf(">> SendMultiSigDistributionTx: committedTx = %s\n", committed.c_str());

	pCurrentAnonymousTxInfo->SetCommittedMsTx(committed);

	return true;
}


int CWallet::GetSelfAddressCount()
{
	int count = 0;

    LOCK(cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& item, mapAddressBook)
    {
		const CBitcoinAddress& address = item.first;
		const std::string& strName = item.second;
		bool fMine = ::IsMine(*this, address.Get());
        if(fMine)
			++count;
    }

	if(fDebugAnon)
		printf(">> GetSelfAddressCount: count = %d\n", count);

	return count;
}


std::string CWallet::GetSelfAddress()
{
	if(selfAddress != "")
		return selfAddress;

	// we want to get a self address. it doesn't matter which address we get, 
	// whether it is an address in the sending selected coins or not.
	std::vector<COutput> vCoins;
	AvailableCoins(vCoins);

	BOOST_FOREACH(const COutput& out, vCoins)
	{
		COutput cout = out;

		while (IsChange(cout.tx->vout[cout.i]) && cout.tx->vin.size() > 0 && IsMine(cout.tx->vin[0]))
		{
			if (!mapWallet.count(cout.tx->vin[0].prevout.hash)) 
				break;
			cout = COutput(&mapWallet[cout.tx->vin[0].prevout.hash], cout.tx->vin[0].prevout.n, 0);
		}

		CTxDestination address;
		if(!ExtractDestination(cout.tx->vout[cout.i].scriptPubKey, address))
			continue;

		if(cout.tx == NULL)
			continue;

		selfAddress = CBitcoinAddress(address).ToString();
		if(fDebugAnon)
			printf(">> selfAddress = %s\n", selfAddress.c_str());

		break;
	}

	return selfAddress;
}


bool CAnonymousTxInfo::SetInitialData(AnonymousTxRole role, std::vector< std::pair<std::string, int64_t> > vecSendInfo0, const CCoinControl* pCoinControl0,
		CNode* pSendNode, CNode* pMixerNode, CNode* pGuarantorNode, CWallet* pWallet)
{
	lastActivityTime = GetTime();

	status = ATX_STATUS_INITDATA;
	size = vecSendInfo0.size();
	if(size == 0) return true;

	vecSendInfo = vecSendInfo0;
	pCoinControl = pCoinControl0;

	std::vector<COutPoint> vOutpoints;
	if(pCoinControl != NULL)
	{
		pCoinControl->ListSelected(vOutpoints);
		if(vOutpoints.size() == 0)
			pCoinControl = NULL;
	}

	std::string text = "Sender";
	if(role == ROLE_MIXER)
		text = "Mixer";
	else if(role == ROLE_GUARANTOR)
		text = "Guarantor";

	text = "Self Role is set to " + text + ".";
	AddToLog(text);

	pParties->SetRole(role);
	if(pSendNode != NULL)
		pParties->SetNode(ROLE_SENDER, pSendNode);

	if(pMixerNode != NULL)
		pParties->SetNode(ROLE_MIXER, pMixerNode);

	if(pGuarantorNode != NULL)
		pParties->SetNode(ROLE_GUARANTOR, pGuarantorNode);

	std::string selfAddress = pWallet->GetSelfAddress();

	if(selfAddress == "")
	{
		if(fDebugAnon)
			printf(">> ERROR. CAnonymousSendInfo::SetInitData: can't find SelfAddress.\n");
		return false;
	}

	std::string selfPubKey = pWallet->GetAddressPubKey(selfAddress);
	pParties->SetAddressAndPubKey(role, selfAddress, selfPubKey);

	text = "Selected SelfAddress = " + selfAddress + ", PublicKey = " + selfPubKey + ".";
	AddToLog(text);

	if(role == ROLE_SENDER)
	{
		long long int now = GetTime();
		char tempa[100];
		sprintf(tempa, "%s-%lld", selfAddress.c_str(), now);
		anonymousId = string(tempa);

		if(fDebugAnon)
			printf(">> anonymousId = %s\n", anonymousId.c_str());

		text = "Created AnonymousId: " + anonymousId + ".";
		AddToLog(text);
	}

	AddToLog("Set Initial Send Info.");

	return true;
}


int64_t CAnonymousTxInfo::GetTotalRequiredCoinsToSend(AnonymousTxRole role)
{
	int64_t baseAmount = 0;
	int64_t finalAmount = 0;
	int64_t fee = 0;

	for(int i = 0; i < size; i++)
		baseAmount += vecSendInfo.at(i).second;
	
	// sender will deposit 2 X BaseAmount + fee, while mixer/guarantor each deposit BaseAmount
	if(role == ROLE_UNKNOWN)
		role = pParties->GetRole();

	switch(role)
	{
		case ROLE_SENDER:
			fee = baseAmount * DEEPSEND_FEE_RATE;
			if(fee < DEEPSEND_MIN_FEE)
				fee = DEEPSEND_MIN_FEE;

			finalAmount = 2 * baseAmount + fee;
			break;

		case ROLE_MIXER:
		case ROLE_GUARANTOR:
			finalAmount = baseAmount;
			break;
	}

	return finalAmount;
}


int64_t CAnonymousTxInfo::GetDepositedAmount(CTransaction tx)
{
	lastActivityTime = GetTime();
	int64_t matchedAmount = 0;
	std::vector<CTxOut> vout = tx.vout;

	BOOST_FOREACH(const CTxOut& out, vout)
	{
		CScript sPubKey = out.scriptPubKey;
		vector<CTxDestination> addresses;
		int nRequired;
		txnouttype type;
		bool b = false;

		if(!ExtractDestinations(sPubKey, type, addresses, nRequired))
			continue;

		BOOST_FOREACH(const CTxDestination& addr, addresses)
		{
			std::string strAddr = CBitcoinAddress(addr).ToString();
			if(strAddr == multiSigAddress)
			{
				b = true;
				break;
			}
		}

		if(b)
			matchedAmount += out.nValue;
	}

	return matchedAmount;
}


bool CAnonymousTxInfo::CheckDeposit(AnonymousTxRole role, CWallet* pWallet)
{
	bool b = false;
	int64_t amount0 = GetTotalRequiredCoinsToSend(role);
	int64_t amount = 0;
	lastActivityTime = GetTime();

	std::string txid = pMultiSigDistributionTx->GetTxid(role);
	uint256 hash;
	hash.SetHex(txid);

	if(pWallet->mapWallet.count(hash))
	{
		if(fDebugAnon)
			printf(">> CheckDeposit: found txid = %s\n", txid.c_str());

		const CWalletTx& wtx = pWallet->mapWallet[hash];
		int64_t nCredit = wtx.GetCredit();
		int64_t nDebit = wtx.GetDebit();
		int64_t nNet = nCredit - nDebit;
		int64_t nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);
		amount = nNet - nFee;
		if(amount < 0)
			amount = - amount;

		if(fDebugAnon)
			printf(">> CheckDeposit: found deposited amount from wtx = %"PRId64"\n", amount);

		if(amount < amount0)
		{
			printf(">> CheckDeposit: did not deposit enough. Expected = %"PRId64", deposited = %"PRId64"\n", amount0, amount);
			return false;
		}
	}
	else
    {
        CTransaction tx;
        uint256 hashBlock = 0;
        if(::GetTransaction(hash, tx, hashBlock))
        {
			if(fDebugAnon)
			{
				printf(">> CheckDeposit: found tx for txid = %s\n", txid.c_str());
				tx.print();
			}

			amount = GetDepositedAmount(tx);
			if(fDebugAnon)
				printf(">> CheckDeposit: found deposited amount from tx = %"PRId64"\n", amount);

			if(amount < amount0)
			{
				printf(">> CheckDeposit: did not deposit enough. Expected = %"PRId64", deposited = %"PRId64"\n", amount0, amount);
				return false;
			}
        }
        else
		{
			if(fDebugAnon)
				printf(">> CheckDeposit: not found txid = %s\n", txid.c_str());
			return false;
		}
	}

	return true;
}


bool CAnonymousTxInfo::CheckDepositTxes(CWallet* pWallet)
{
	lastActivityTime = GetTime();
	if(fDebugAnon)
		printf(">> CheckDepositTxes: Verify sender's deposit.\n");
	bool b = CheckDeposit(ROLE_SENDER, pWallet);
	if(!b)
	{
		if(fDebugAnon)
			printf(">> CheckDepositTxes: sender's deposit verification failed.\n");
		return false;
	}

	if(fDebugAnon)
		printf(">> CheckDepositTxes: Verify mixer's deposit.\n");
	b = CheckDeposit(ROLE_MIXER, pWallet);
	if(!b)
	{
		if(fDebugAnon)
			printf(">> CheckDepositTxes: mixer's deposit verification failed.\n");
		return false;
	}

	if(fDebugAnon)
		printf(">> CheckDepositTxes: Verify guarantor's deposit.\n");
	b = CheckDeposit(ROLE_GUARANTOR, pWallet);
	if(!b)
	{
		if(fDebugAnon)
			printf(">> CheckDepositTxes: guarantor's deposit verification failed.\n");
		return false;
	}

	return true;
}


bool CAnonymousTxInfo::CheckSendTx(CWallet* pWallet)
{
	bool b = false;
	int64_t amount0 = 0;
	int64_t amount = 0;
	lastActivityTime = GetTime();

	uint256 hash;
	hash.SetHex(sendTx);

	if(pWallet->mapWallet.count(hash))
	{
		if(fDebugAnon)
			printf(">> found send txid for %s\n", sendTx.c_str());

		const CWalletTx& wtx = pWallet->mapWallet[hash];
		int64_t nCredit = wtx.GetCredit();
		int64_t nDebit = wtx.GetDebit();
		int64_t nNet = nCredit - nDebit;
		int64_t nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);
		amount = nNet - nFee;
		amount0 = GetTotalRequiredCoinsToSend(ROLE_MIXER);

		if(amount < amount0)
		{
			printf(">> Mixer did not send enough to destination. Expected = %"PRId64", deposited = %"PRId64"\n", amount0, amount);
			return false;
		}
	}
	else
    {
        CTransaction tx;
        uint256 hashBlock = 0;
        if(::GetTransaction(hash, tx, hashBlock))
        {
			if(fDebugAnon)
			{
				printf(">> CheckSendTx: found tx for sendTx = %s\n", sendTx.c_str());
				tx.print();
			}

			amount = GetDepositedAmount(tx);
			if(fDebugAnon)
				printf(">> CheckSendTx: found deposited amount from tx = %"PRId64"\n", amount);

			if(amount < amount0)
			{
				printf(">> CheckSendTx: did not send enough. Expected = %"PRId64", deposited = %"PRId64"\n", amount0, amount);
				return false;
			}
        }
        else
		{
			if(fDebugAnon)
				printf(">> CheckSendTx: not found sendTx = %s\n", sendTx.c_str());
			return false;
		}
	}

	return true;
}


bool CAnonymousTxInfo::IsCurrentTxInProcess() const
{
	if((status == ATX_STATUS_NONE) || (status == ATX_STATUS_COMPLETE))
		return false;

	return true;
}


bool CAnonymousTxInfo::CanReset() const
{
	static int64_t MAXIMUM_TRANSACTION_TIMEOUT = 180; // 3 mins, in first few steps, no reply allows remove

	if(status < 5)	// before escrow deoposited
	{
		int64_t now = GetTime();
		if((now - lastActivityTime) > MAXIMUM_TRANSACTION_TIMEOUT)	
		{
			return true;
		}
	}

	return false;
}


void CAnonymousTxInfo::AddToLog(std::string text)
{
	std::string logtext = currentDateTime() + ": " + text;
	logs.push_back(logtext);
}


std::string CAnonymousTxInfo::GetLastAnonymousTxLog()
{
	std::string logText = "";
	if(logs.empty())
	{
		logText = "No Anonymous Transaction Info available\n";
		return logText;
	}

	logText = "The status of last/current transaction: ";
	switch (status)
	{
		case ATX_STATUS_RESERVE:
			logText += "ATX_STATUS_RESERVE (Service Reserved).\n\n";
			break;

		case ATX_STATUS_INITDATA:
			logText += "ATX_STATUS_INITDATA (Initial Data Set).\n\n";
			break;

		case ATX_STATUS_PUBKEY:
			logText += "ATX_STATUS_PUBKEY (All public keys are available).\n\n";
			break;

		case ATX_STATUS_MSADDR:
			logText += "ATX_STATUS_MSADDR (2-of-3 multisig address created).\n\n";
			break;

		case ATX_STATUS_MSDEPO:
			logText += "ATX_STATUS_MSDEPO (Deposits to 2-of-3 multisig address completed).\n\n";
			break;

		case ATX_STATUS_MSDEPV:
			logText += "ATX_STATUS_MSDEPV (Desposits to 2-of-3 multisig address verified).\n\n";
			break;

		case ATX_STATUS_MSTXR0:
			logText += "ATX_STATUS_MSTXR0 (Multisig distribution transaction created).\n\n";
			break;

		case ATX_STATUS_MSTXR1:
			logText += "ATX_STATUS_MSTXR1 (Multisig distribution transaction signed once).\n\n";
			break;

		case ATX_STATUS_MSTXRC:
			logText += "ATX_STATUS_MSTXRC (Multisig distribution transaction signed twice - complete).\n\n";
			break;

		case ATX_STATUS_COMPLETE:
			logText += "ATX_STATUS_COMPLETE (Anonymous transaction completed).\n\n";
			break;
	}

	for(int i = 0; i < logs.size(); i++)
	{
		logText += logs.at(i) + "\n";
	}

	logText += "\n\n";

	return logText;
}


std::string CAnonymousTxInfo::GetNodeIpAddress(AnonymousTxRole role0) const
{
	CNode* pNode = GetNode(role0);

	if(pNode == NULL)
		return "";

	string nodeAddr = pNode->addrName;
	nodeAddr = nodeAddr.substr(0, nodeAddr.find(":"));
	return nodeAddr;
}


int CWallet::GetBestBlockHeight()
{
	return nBestHeight;
}


bool CWallet::NewStealthAddress(std::string& sError, std::string& sLabel, CStealthAddress& sxAddr)
{
    ec_secret scan_secret;
    ec_secret spend_secret;
    
    if (GenerateRandomSecret(scan_secret) != 0
        || GenerateRandomSecret(spend_secret) != 0)
    {
        sError = "GenerateRandomSecret failed.";
        printf("Error CWallet::NewStealthAddress - %s\n", sError.c_str());
        return false;
    }
    
    ec_point scan_pubkey, spend_pubkey;
    if (SecretToPublicKey(scan_secret, scan_pubkey) != 0)
    {
        sError = "Could not get scan public key.";
        printf("Error CWallet::NewStealthAddress - %s\n", sError.c_str());
        return false;
    }
    
    if (SecretToPublicKey(spend_secret, spend_pubkey) != 0)
    {
        sError = "Could not get spend public key.";
        printf("Error CWallet::NewStealthAddress - %s\n", sError.c_str());
        return false;
    }
    
    if (fDebug)
    {
        printf("getnewstealthaddress: ");
        printf("scan_pubkey ");
        for (uint32_t i = 0; i < scan_pubkey.size(); ++i)
          printf("%02x", scan_pubkey[i]);
        printf("\n");
        
        printf("spend_pubkey ");
        for (uint32_t i = 0; i < spend_pubkey.size(); ++i)
          printf("%02x", spend_pubkey[i]);
        printf("\n");
    }
    
    sxAddr.label = sLabel;
    sxAddr.scan_pubkey = scan_pubkey;
    sxAddr.spend_pubkey = spend_pubkey;
    
    sxAddr.scan_secret.resize(32);
    memcpy(&sxAddr.scan_secret[0], &scan_secret.e[0], 32);
    sxAddr.spend_secret.resize(32);
    memcpy(&sxAddr.spend_secret[0], &spend_secret.e[0], 32);
    
    return true;
}

bool CWallet::AddStealthAddress(CStealthAddress& sxAddr)
{
    LOCK(cs_wallet);
    
    // must add before changing spend_secret
    stealthAddresses.insert(sxAddr);
    
    bool fOwned = sxAddr.scan_secret.size() == ec_secret_size;
    
    
    
    if (fOwned)
    {
        // -- owned addresses can only be added when wallet is unlocked
        if (IsLocked())
        {
            printf("Error: CWallet::AddStealthAddress wallet must be unlocked.\n");
            stealthAddresses.erase(sxAddr);
            return false;
        }
        
        if (IsCrypted())
        {
            std::vector<unsigned char> vchCryptedSecret;
            CSecret vchSecret;
            vchSecret.resize(32);
            memcpy(&vchSecret[0], &sxAddr.spend_secret[0], 32);
            
            uint256 iv = Hash(sxAddr.spend_pubkey.begin(), sxAddr.spend_pubkey.end());
            if (!EncryptSecret(vMasterKey, vchSecret, iv, vchCryptedSecret))
            {
                printf("Error: Failed encrypting stealth key %s\n", sxAddr.Encoded().c_str());
                stealthAddresses.erase(sxAddr);
                return false;
            }
            sxAddr.spend_secret = vchCryptedSecret;
        }
    }
    
    bool rv = CWalletDB(strWalletFile).WriteStealthAddress(sxAddr);
    
    if (rv)
        NotifyAddressBookChanged(this, sxAddr, sxAddr.label, fOwned, CT_NEW);
    
    return rv;
}

bool CWallet::UnlockStealthAddresses(const CKeyingMaterial& vMasterKeyIn)
{
    // -- decrypt spend_secret of stealth addresses
    std::set<CStealthAddress>::iterator it;
    for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
    {
        if (it->scan_secret.size() < 32)
            continue; // stealth address is not owned
        
        // -- CStealthAddress are only sorted on spend_pubkey
        CStealthAddress &sxAddr = const_cast<CStealthAddress&>(*it);
        
        if (fDebug)
            printf("Decrypting stealth key %s\n", sxAddr.Encoded().c_str());
        
        CSecret vchSecret;
        uint256 iv = Hash(sxAddr.spend_pubkey.begin(), sxAddr.spend_pubkey.end());
        if(!DecryptSecret(vMasterKeyIn, sxAddr.spend_secret, iv, vchSecret)
            || vchSecret.size() != 32)
        {
            printf("Error: Failed decrypting stealth key %s\n", sxAddr.Encoded().c_str());
            continue;
        }
        
        ec_secret testSecret;
        memcpy(&testSecret.e[0], &vchSecret[0], 32);
        ec_point pkSpendTest;
        
        if (SecretToPublicKey(testSecret, pkSpendTest) != 0
            || pkSpendTest != sxAddr.spend_pubkey)
        {
            printf("Error: Failed decrypting stealth key, public key mismatch %s\n", sxAddr.Encoded().c_str());
            continue;
        }
        
        sxAddr.spend_secret.resize(32);
        memcpy(&sxAddr.spend_secret[0], &vchSecret[0], 32);
    }
    
    CryptedKeyMap::iterator mi = mapCryptedKeys.begin();
    for (; mi != mapCryptedKeys.end(); ++mi)
    {
        CPubKey &pubKey = (*mi).second.first;
        std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        if (vchCryptedSecret.size() != 0)
            continue;
        
        CKeyID ckid = pubKey.GetID();
        CBitcoinAddress addr(ckid);
        
        StealthKeyMetaMap::iterator mi = mapStealthKeyMeta.find(ckid);
        if (mi == mapStealthKeyMeta.end())
        {
            printf("Error: No metadata found to add secret for %s\n", addr.ToString().c_str());
            continue;
        }
        
        CStealthKeyMetadata& sxKeyMeta = mi->second;
        
        CStealthAddress sxFind;
        sxFind.scan_pubkey = sxKeyMeta.pkScan.Raw();
        
        std::set<CStealthAddress>::iterator si = stealthAddresses.find(sxFind);
        if (si == stealthAddresses.end())
        {
            printf("No stealth key found to add secret for %s\n", addr.ToString().c_str());
            continue;
        }
        
        if (fDebug)
            printf("Expanding secret for %s\n", addr.ToString().c_str());
        
        ec_secret sSpendR;
        ec_secret sSpend;
        ec_secret sScan;
        
        if (si->spend_secret.size() != ec_secret_size
            || si->scan_secret.size() != ec_secret_size)
        {
            printf("Stealth address has no secret key for %s\n", addr.ToString().c_str());
            continue;
        }
        memcpy(&sScan.e[0], &si->scan_secret[0], ec_secret_size);
        memcpy(&sSpend.e[0], &si->spend_secret[0], ec_secret_size);
        
        ec_point pkEphem = sxKeyMeta.pkEphem.Raw();
        if (StealthSecretSpend(sScan, pkEphem, sSpend, sSpendR) != 0)
        {
            printf("StealthSecretSpend() failed.\n");
            continue;
        }
        
        ec_point pkTestSpendR;
        if (SecretToPublicKey(sSpendR, pkTestSpendR) != 0)
        {
            printf("SecretToPublicKey() failed.\n");
            continue;
        }
        
        CSecret vchSecret;
        vchSecret.resize(ec_secret_size);
        
        memcpy(&vchSecret[0], &sSpendR.e[0], ec_secret_size);
        CKey ckey;
        
        try {
            ckey.SetSecret(vchSecret, true);
        } catch (std::exception& e) {
            printf("ckey.SetSecret() threw: %s.\n", e.what());
            continue;
        }
        
        CPubKey cpkT = ckey.GetPubKey();
              
        if (!cpkT.IsValid())
        {
            printf("cpkT is invalid.\n");
            continue;
        }
        
        if (cpkT != pubKey)
        {
            printf("Error: Generated secret does not match.\n");
            if (fDebug)
            {
                printf("cpkT   %s\n", HexStr(cpkT.Raw()).c_str());
                printf("pubKey %s\n", HexStr(pubKey.Raw()).c_str());
            }
            continue;
        }
        
        if (!ckey.IsValid())
        {
            printf("Reconstructed key is invalid.\n");
            continue;
        }
        
        if (fDebug)
        {
            CKeyID keyID = cpkT.GetID();
            CBitcoinAddress coinAddress(keyID);
            printf("Adding secret to key %s.\n", coinAddress.ToString().c_str());
        }
        
        if (!AddKey(ckey))
        {
            printf("AddKey failed.\n");
            continue;
        }
        
        if (!CWalletDB(strWalletFile).EraseStealthKeyMeta(ckid))
            printf("EraseStealthKeyMeta failed for %s\n", addr.ToString().c_str());
    }
    return true;
}

bool CWallet::UpdateStealthAddress(std::string &addr, std::string &label, bool addIfNotExist)
{
    if (fDebug)
        printf("UpdateStealthAddress %s\n", addr.c_str());
    
    
    CStealthAddress sxAddr;
    
    if (!sxAddr.SetEncoded(addr))
        return false;
    
    std::set<CStealthAddress>::iterator it;
    it = stealthAddresses.find(sxAddr);
    
    ChangeType nMode = CT_UPDATED;
    CStealthAddress sxFound;
    if (it == stealthAddresses.end())
    {
        if (addIfNotExist)
        {
            sxFound = sxAddr;
            sxFound.label = label;
            stealthAddresses.insert(sxFound);
            nMode = CT_NEW;
        } else
        {
            printf("UpdateStealthAddress %s, not in set\n", addr.c_str());
            return false;
        }
    } else
    {
        sxFound = const_cast<CStealthAddress&>(*it);
        
        if (sxFound.label == label)
        {
            // no change
            return true;
        }
    }
    
    sxFound.label = label;
    
    if (!CWalletDB(strWalletFile).WriteStealthAddress(sxFound))
    {
        printf("UpdateStealthAddress(%s) Write to db failed.\n", addr.c_str());
        return false;
    }
    
    bool fOwned = sxFound.scan_secret.size() == ec_secret_size;
    NotifyAddressBookChanged(this, sxFound, sxFound.label, fOwned, nMode);
    
    return true;
}

bool CWallet::CreateStealthTransaction(CScript scriptPubKey, int64_t nValue, std::vector<uint8_t>& P, std::vector<uint8_t>& narr, std::string& sNarr, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    vector< pair<CScript, int64_t> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    
    CScript scriptP = CScript() << OP_RETURN << P;
    if (narr.size() > 0) {
        scriptP = scriptP << OP_RETURN << narr;
    }
    vecSend.push_back(make_pair(scriptP, nTransactionFee));

    // -- shuffle inputs, change output won't mix enough as it must be not fully random for plantext narrations
    std::random_shuffle(vecSend.begin(), vecSend.end());
    
    bool rv = CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet);
    
    // -- the change txn is inserted in a random pos, check here to match narr to output
    if (rv && narr.size() > 0)
    {
        for (unsigned int k = 0; k < wtxNew.vout.size(); ++k)
        {
            if (wtxNew.vout[k].scriptPubKey != scriptPubKey
                || wtxNew.vout[k].nValue != nValue)
                continue;
            
            char key[64];
            if (snprintf(key, sizeof(key), "n_%u", k) < 1)
            {
                printf("CreateStealthTransaction(): Error creating narration key.");
                break;
            }
            wtxNew.mapValue[key] = sNarr;
            break;
        }
    }
    
    return rv;
}

string CWallet::SendStealthMoney(CScript scriptPubKey, int64_t nValue, std::vector<uint8_t>& P, std::vector<uint8_t>& narr, std::string& sNarr, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendStealthMoney() : %s", strError.c_str());
        return strError;
    }
    if (fWalletUnlockStakingOnly)
    {
        string strError = _("Error: Wallet unlocked for staking only, unable to create transaction.");
        printf("SendStealthMoney() : %s", strError.c_str());
        return strError;
    }
    if (!CreateStealthTransaction(scriptPubKey, nValue, P, narr, sNarr, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendStealthMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired, _("Sending...")))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}

bool CWallet::SendStealthMoneyToDestination(CStealthAddress& sxAddress, int64_t nValue, std::string& sNarr, CWalletTx& wtxNew, std::string& sError, bool fAskFee)
{
    // -- Check amount
    if (nValue <= 0)
    {
        sError = "Invalid amount";
        return false;
    }
    if (nValue + nTransactionFee > GetBalance())
    {
        sError = "Insufficient funds";
        return false;
    }
    
    
    ec_secret ephem_secret;
    ec_secret secretShared;
    ec_point pkSendTo;
    ec_point ephem_pubkey;
    
    if (GenerateRandomSecret(ephem_secret) != 0)
    {
        sError = "GenerateRandomSecret failed.";
        return false;
    }
    
    if (StealthSecret(ephem_secret, sxAddress.scan_pubkey, sxAddress.spend_pubkey, secretShared, pkSendTo) != 0)
    {
        sError = "Could not generate receiving public key.";
        return false;
    }
    
    CPubKey cpkTo(pkSendTo);
    if (!cpkTo.IsValid())
    {
        sError = "Invalid public key generated.";
        return false;
    }
    
    CKeyID ckidTo = cpkTo.GetID();
    
    CBitcoinAddress addrTo(ckidTo);
    
    if (SecretToPublicKey(ephem_secret, ephem_pubkey) != 0)
    {
        sError = "Could not generate ephem public key.";
        return false;
    }
    
    if (fDebug)
    {
        printf("Stealth send to generated pubkey %" PRIszu": %s\n", pkSendTo.size(), HexStr(pkSendTo).c_str());
        printf("hash %s\n", addrTo.ToString().c_str());
        printf("ephem_pubkey %" PRIszu": %s\n", ephem_pubkey.size(), HexStr(ephem_pubkey).c_str());
    }
    
    std::vector<unsigned char> vchNarr;
    if (sNarr.length() > 0)
    {
        SecMsgCrypter crypter;
        crypter.SetKey(&secretShared.e[0], &ephem_pubkey[0]);
        
        if (!crypter.Encrypt((uint8_t*)&sNarr[0], sNarr.length(), vchNarr))
        {
            sError = "Narration encryption failed.";
            return false;
        }
        
        if (vchNarr.size() > 48)
        {
            sError = "Encrypted narration is too long.";
            return false;
        }
    }
    
    // -- Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(addrTo.Get());
    
    if ((sError = SendStealthMoney(scriptPubKey, nValue, ephem_pubkey, vchNarr, sNarr, wtxNew, fAskFee)) != "")
        return false;
    
    
    return true;
}

bool CWallet::FindStealthTransactions(const CTransaction& tx, mapValue_t& mapNarr)
{
    if (fDebug)
        printf("FindStealthTransactions() tx: %s\n", tx.GetHash().GetHex().c_str());
    
    mapNarr.clear();
    
    LOCK(cs_wallet);
    ec_secret sSpendR;
    ec_secret sSpend;
    ec_secret sScan;
    ec_secret sShared;
    
    ec_point pkExtracted;
    
    std::vector<uint8_t> vchEphemPK;
    std::vector<uint8_t> vchDataB;
    std::vector<uint8_t> vchENarr;
    opcodetype opCode;
    char cbuf[256];
    
    int32_t nOutputIdOuter = -1;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nOutputIdOuter++;
        // -- for each OP_RETURN need to check all other valid outputs
        
        //printf("txout scriptPubKey %s\n",  txout.scriptPubKey.ToString().c_str());
        CScript::const_iterator itTxA = txout.scriptPubKey.begin();
        
        if (!txout.scriptPubKey.GetOp(itTxA, opCode, vchEphemPK)
            || opCode != OP_RETURN)
            continue;
        else
        if (!txout.scriptPubKey.GetOp(itTxA, opCode, vchEphemPK)
            || vchEphemPK.size() != 33)
        {
            // -- look for plaintext narrations
            if (vchEphemPK.size() > 1
                && vchEphemPK[0] == 'n'
                && vchEphemPK[1] == 'p')
            {
                if (txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && opCode == OP_RETURN
                    && txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && vchENarr.size() > 0)
                {
                    std::string sNarr = std::string(vchENarr.begin(), vchENarr.end());
                    
                    snprintf(cbuf, sizeof(cbuf), "n_%d", nOutputIdOuter-1); // plaintext narration always matches preceding value output
                    mapNarr[cbuf] = sNarr;
                } else
                {
                    printf("Warning: FindStealthTransactions() tx: %s, Could not extract plaintext narration.\n", tx.GetHash().GetHex().c_str());
                }
            }
            
            continue;
        }
        
        int32_t nOutputId = -1;
        nStealth++;
        BOOST_FOREACH(const CTxOut& txoutB, tx.vout)
        {
            nOutputId++;
            
            if (&txoutB == &txout)
                continue;
            
            bool txnMatch = false; // only 1 txn will match an ephem pk
            //printf("txoutB scriptPubKey %s\n",  txoutB.scriptPubKey.ToString().c_str());
            
            CTxDestination address;
            if (!ExtractDestination(txoutB.scriptPubKey, address))
                continue;
            
            if (address.type() != typeid(CKeyID))
                continue;
            
            CKeyID ckidMatch = boost::get<CKeyID>(address);
            
            if (HaveKey(ckidMatch)) // no point checking if already have key
                continue;
            
            std::set<CStealthAddress>::iterator it;
            for (it = stealthAddresses.begin(); it != stealthAddresses.end(); ++it)
            {
                if (it->scan_secret.size() != ec_secret_size)
                    continue; // stealth address is not owned
                
                //printf("it->Encoded() %s\n",  it->Encoded().c_str());
                memcpy(&sScan.e[0], &it->scan_secret[0], ec_secret_size);
                
                if (StealthSecret(sScan, vchEphemPK, it->spend_pubkey, sShared, pkExtracted) != 0)
                {
                    printf("StealthSecret failed.\n");
                    continue;
                };
                //printf("pkExtracted %"PRIszu": %s\n", pkExtracted.size(), HexStr(pkExtracted).c_str());
                
                CPubKey cpkE(pkExtracted);
                
                if (!cpkE.IsValid())
                    continue;
                CKeyID ckidE = cpkE.GetID();
                
                if (ckidMatch != ckidE)
                    continue;
                
                if (fDebug)
                    printf("Found stealth txn to address %s\n", it->Encoded().c_str());
                
                if (IsLocked())
                {
                    if (fDebug)
                        printf("Wallet is locked, adding key without secret.\n");
                    
                    // -- add key without secret
                    std::vector<uint8_t> vchEmpty;
                    AddCryptedKey(cpkE, vchEmpty);
                    CKeyID keyId = cpkE.GetID();
                    CBitcoinAddress coinAddress(keyId);
                    std::string sLabel = it->Encoded();
                    SetAddressBookName(keyId, sLabel);
                    
                    CPubKey cpkEphem(vchEphemPK);
                    CPubKey cpkScan(it->scan_pubkey);
                    CStealthKeyMetadata lockedSkMeta(cpkEphem, cpkScan);
                    
                    if (!CWalletDB(strWalletFile).WriteStealthKeyMeta(keyId, lockedSkMeta))
                        printf("WriteStealthKeyMeta failed for %s\n", coinAddress.ToString().c_str());
                    
                    mapStealthKeyMeta[keyId] = lockedSkMeta;
                    nFoundStealth++;
                } else
                {
                    if (it->spend_secret.size() != ec_secret_size)
                        continue;
                    memcpy(&sSpend.e[0], &it->spend_secret[0], ec_secret_size);
                    
                    
                    if (StealthSharedToSecretSpend(sShared, sSpend, sSpendR) != 0)
                    {
                        printf("StealthSharedToSecretSpend() failed.\n");
                        continue;
                    }
                   
                    ec_point pkTestSpendR;
                    if (SecretToPublicKey(sSpendR, pkTestSpendR) != 0)
                    {
                        printf("SecretToPublicKey() failed.\n");
                        continue;
                    }
                    
                    CSecret vchSecret;
                    vchSecret.resize(ec_secret_size);
                    
                    memcpy(&vchSecret[0], &sSpendR.e[0], ec_secret_size);
                    CKey ckey;
                    
                    try {
                        ckey.SetSecret(vchSecret, true);
                    } catch (std::exception& e) {
                        printf("ckey.SetSecret() threw: %s.\n", e.what());
                        continue;
                    }
                    
                    CPubKey cpkT = ckey.GetPubKey();
                    if (!cpkT.IsValid())
                    {
                        printf("cpkT is invalid.\n");
                        continue;
                    }
                    
                    if (!ckey.IsValid())
                    {
                        printf("Reconstructed key is invalid.\n");
                        continue;
                    }
                    
                    CKeyID keyID = cpkT.GetID();
                    if (fDebug)
                    {
                        CBitcoinAddress coinAddress(keyID);
                        printf("Adding key %s.\n", coinAddress.ToString().c_str());
                    }
                    
                    if (!AddKey(ckey))
                    {
                        printf("AddKey failed.\n");
                        continue;
                    }
                    
                    std::string sLabel = it->Encoded();
                    SetAddressBookName(keyID, sLabel);
                    nFoundStealth++;
                }
                
                if (txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && opCode == OP_RETURN
                    && txout.scriptPubKey.GetOp(itTxA, opCode, vchENarr)
                    && vchENarr.size() > 0)
                {
                    SecMsgCrypter crypter;
                    crypter.SetKey(&sShared.e[0], &vchEphemPK[0]);
                    std::vector<uint8_t> vchNarr;
                    if (!crypter.Decrypt(&vchENarr[0], vchENarr.size(), vchNarr))
                    {
                        printf("Decrypt narration failed.\n");
                        continue;
                    }
                    std::string sNarr = std::string(vchNarr.begin(), vchNarr.end());
                    
                    snprintf(cbuf, sizeof(cbuf), "n_%d", nOutputId);
                    mapNarr[cbuf] = sNarr;
                }
                
                txnMatch = true;
                break;
            }
            if (txnMatch)
                break;
        }
    }
    
    return true;
}

