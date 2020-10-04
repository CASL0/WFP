#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <string>
#include <vector>
#include <stdint.h>

#include <fwpmu.h>
#pragma comment (lib,"fwpuclnt.lib")

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib")


typedef struct
{
    uint32_t hexAddr;
    UINT64 filterID;
} FILTER_ADDR_INFO;


// Firewallエンジン
HANDLE g_hEngine = nullptr;

//SubLayerID
GUID g_subLayerGUID = { 0 };

//filterID
UINT64 g_AllBlockfilterID = 0;

//filter conditionに指定するIPアドレスリスト
//stringフォーマットのIPアドレス
std::vector<std::string> g_vecsAddr =
{
    std::string("192.218.88.180"),
    std::string("76.74.234.210"),
};

//
std::vector<FILTER_ADDR_INFO> g_vecFilterAddrInfo;

//プロトタイプ宣言
DWORD AddSubLayer(void);
DWORD RemoveSubLayer(void);
DWORD AddPermitFilter(void);
DWORD AddBlockFilter(void);
DWORD RemoveFilter(void);
DWORD BuildFilterAddrInfo(std::vector<std::string> vecsAddr);

int main()
{

    DWORD ret = ERROR_BAD_COMMAND;
    ret = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &g_hEngine);
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "FwpmEngineOpen0 failed with error: " << ret << std::endl;
        return 1;
    }

    ret = AddSubLayer();
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "AddSubLayer failed with error: " << ret << std::endl;
        return 1;
    }

    ret = AddPermitFilter();
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "AddPermitFilter failed with error: " << ret << std::endl;
        return 1;
    }

    ret = AddBlockFilter();
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "AddBlockFilter failed with error: " << ret << std::endl;
        return 1;
    }

    std::cerr << "Press any key to stop firewall..." << std::endl;
    _getch();

    ret = RemoveFilter();
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "RemoveFilter failed with error: " << ret << std::endl;
        return 1;
    }
    ret = RemoveSubLayer();
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "RemoveSubLayer failed with error: " << ret << std::endl;
        return 1;
    }

    if (g_hEngine != nullptr)
    {
        ret = FwpmEngineClose0(g_hEngine);
        if (ret != ERROR_SUCCESS)
        {
            std::cerr << "FwpmEngineClose0 failed with error: " << ret << std::endl;
            return 1;
        }
    }

    return 0;

}

DWORD AddSubLayer(void)
{
    FWPM_SUBLAYER0 fwpSubLayer = { 0 };
    RPC_STATUS rpcStatus = RPC_S_OK;

    //GUIDの生成
    //  SubLayerKeyメンバはSubLayerを表す識別子
    rpcStatus = UuidCreate(&fwpSubLayer.subLayerKey);
    if (rpcStatus != RPC_S_OK)
    {
        std::cerr << "UuidCreate failed with error: " << rpcStatus << std::endl;
        return ERROR_BAD_COMMAND;
    }
    CopyMemory(&g_subLayerGUID, &fwpSubLayer.subLayerKey, sizeof(fwpSubLayer.subLayerKey));

    //displayDataメンバは識別しやすくするための名前
    //自由に付けて良い
    fwpSubLayer.displayData.name = const_cast<wchar_t*>(L"WFP example");
    fwpSubLayer.displayData.description = const_cast<wchar_t*>(L"create WFP example");
    fwpSubLayer.flags = 0;
    fwpSubLayer.weight = 0x100;

    std::cerr << "Adding SubLayer\n";
    DWORD ret = FwpmSubLayerAdd0(g_hEngine, &fwpSubLayer, nullptr);

    return ret;

}

DWORD BuildFilterAddrInfo(std::vector<std::string> vecsAddr)
{
    DWORD ret = ERROR_BAD_COMMAND;
    WSADATA wsaData;
    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "WSAStartup failed with error: " << ret << std::endl;
        return ret;
    }

    for (auto& elem : vecsAddr)
    {
        FILTER_ADDR_INFO addrInfo;
        in_addr hexAddr;
        int iRet = inet_pton(AF_INET, elem.c_str(), &hexAddr);
        if (iRet != 1)
        {
            std::cerr << "inet_pton failed with error: " << GetLastError() << std::endl;
            WSACleanup();
            return ERROR_BAD_COMMAND;
        }
        addrInfo.hexAddr = ntohl(hexAddr.S_un.S_addr);
        g_vecFilterAddrInfo.push_back(addrInfo);
    }
    WSACleanup();
    return ERROR_SUCCESS;
}

DWORD AddPermitFilter(void)
{
    DWORD ret = ERROR_BAD_COMMAND;

    ret = BuildFilterAddrInfo(g_vecsAddr);
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "BuildFilterAddrInfo failed with error: " << ret << std::endl;
        return ret;
    }
    for (auto& elem : g_vecFilterAddrInfo)
    {
        FWPM_FILTER0 fwpFilter = { 0 };
        FWPM_FILTER_CONDITION0 fwpCondition = { 0 };
        FWP_V4_ADDR_AND_MASK fwpAddrMask = { 0 };

        fwpFilter.subLayerKey = g_subLayerGUID;

        //filterの種類を指定
        //https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
        fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

        fwpFilter.action.type = FWP_ACTION_PERMIT;
        fwpFilter.weight.type = FWP_EMPTY;

        fwpFilter.displayData.name = const_cast<wchar_t*>(L"IPv4Block");
        fwpFilter.displayData.description = const_cast<wchar_t*>(L"Filter to block specific outbound connections.");

        fwpFilter.numFilterConditions = 1;
        fwpFilter.filterCondition = &fwpCondition;

        //特定のIP向かいの通信を遮断
        //https://docs.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
        fwpCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        fwpCondition.matchType = FWP_MATCH_EQUAL;
        fwpCondition.conditionValue.type = FWP_V4_ADDR_MASK;
        fwpCondition.conditionValue.v4AddrMask = &fwpAddrMask;

        //ホストオーダーでIPを登録
        fwpAddrMask.addr = elem.hexAddr;
        fwpAddrMask.mask = 0xffffffff;

        std::cerr << "Adding filter\n";
        ret = FwpmFilterAdd0(g_hEngine, &fwpFilter, nullptr, &elem.filterID);
        if (ret != ERROR_SUCCESS)
        {
            std::cerr << "FwpmFilterAdd0 failed with error: " << ret << std::endl;
            return ret;
        }
    }

    return ret;
}

DWORD AddBlockFilter(void)
{
    DWORD ret = ERROR_BAD_COMMAND;

    FWPM_FILTER0 fwpFilter = { 0 };
    fwpFilter.subLayerKey = g_subLayerGUID;

    fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    fwpFilter.action.type = FWP_ACTION_BLOCK;
    fwpFilter.weight.type = FWP_EMPTY;
    fwpFilter.displayData.name = const_cast<wchar_t*>(L"ALLBlock");
    fwpFilter.displayData.description = const_cast<wchar_t*>(L"Filter to block all outbound connections.");
    
    //numFilterConditionsを0に指定するとすべての通信を遮断
    fwpFilter.numFilterConditions = 0;
    
    std::cerr << "Adding filter\n";
    ret = FwpmFilterAdd0(g_hEngine, &fwpFilter, nullptr, &g_AllBlockfilterID);
    return ret;

}

DWORD RemoveSubLayer(void)
{
    std::cerr << "Removing SubLayer\n";
    DWORD ret = FwpmSubLayerDeleteByKey0(g_hEngine, &g_subLayerGUID);
    ZeroMemory(&g_subLayerGUID, sizeof(GUID));

    return ret;
}

DWORD RemoveFilter(void)
{
    DWORD ret = ERROR_BAD_COMMAND;
    for (auto& elem : g_vecFilterAddrInfo)
    {
        std::cerr << "Removing Filter\n";
        ret = FwpmFilterDeleteById0(g_hEngine, elem.filterID);
        if (ret != ERROR_SUCCESS)
        {
            std::cerr << "FwpmFilterDeleteById0 failed with error: " << ret << std::endl;
            return ret;
        }

    }
    ret = FwpmFilterDeleteById0(g_hEngine, g_AllBlockfilterID);
    return ret;

}