
#include <iostream>
#include <Windows.h>
#include <conio.h>

#include <fwpmu.h>
#pragma comment (lib,"fwpuclnt.lib")

#pragma comment(lib, "Rpcrt4.lib")


// Firewallエンジン
HANDLE g_hEngine = nullptr;

//SubLayerID
GUID g_subLayerGUID = { 0 };

//filterID
UINT64 g_filterIDv4 = 0;
UINT64 g_filterIDv6 = 0;

//プロトタイプ宣言
DWORD AddSubLayer(void);
DWORD RemoveSubLayer(void);
DWORD AddFilter(void);
DWORD RemoveFilter(void);

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

    ret = AddFilter();
    if (ret != ERROR_SUCCESS)
    {
        std::cerr << "AddFilter failed with error: " << ret << std::endl;
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

DWORD AddFilter(void)
{
    DWORD ret = ERROR_BAD_COMMAND;

    FWPM_FILTER0 fwpFilter = { 0 };

    fwpFilter.subLayerKey = g_subLayerGUID;

    //filterの種類を指定
    //https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    fwpFilter.action.type = FWP_ACTION_BLOCK;

    fwpFilter.weight.type = FWP_EMPTY;
    fwpFilter.displayData.name = const_cast<wchar_t*>(L"ALLBlock");
    fwpFilter.displayData.description = const_cast<wchar_t*>(L"Filter to block all outbound connections.");
    
    //numFilterConditionsを０に指定するとすべての通信を遮断
    fwpFilter.numFilterConditions = 0;

    std::cerr << "Adding filter\n";
    ret = FwpmFilterAdd0(g_hEngine, &fwpFilter, nullptr, &g_filterIDv4);
    fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    ret = FwpmFilterAdd0(g_hEngine, &fwpFilter, nullptr, &g_filterIDv6);
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
    std::cerr << "Removing Filter\n";
    DWORD ret = FwpmFilterDeleteById0(g_hEngine, g_filterIDv4);
    ret = FwpmFilterDeleteById0(g_hEngine, g_filterIDv6);
    return ret;

}