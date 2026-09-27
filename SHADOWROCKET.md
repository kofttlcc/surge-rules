# Shadowrocket（iOS）版本

本版本基於 [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) 的 `release/ruleset` 資料產生，保留 GPL-3.0 授權。原有 Surge 檔案及發布流程保留，Shadowrocket 產物使用獨立 `shadowrocket-release` 分支。

## 在 iPhone／iPad 匯入

先在 Shadowrocket 首頁匯入自己的節點或訂閱，選擇可用節點。這份設定只提供分流，不提供代理伺服器。

1. Shadowrocket →「配置」→ 右上角「＋」。
2. 貼上以下網址並下載：

   ```text
   https://raw.githubusercontent.com/kofttlcc/surge-rules/shadowrocket-release/shadowrocket.conf
   ```

3. 點擊下載的設定 →「使用配置」，完成編譯並確認遠端規則集成功載入。
4. 首頁 →「全局路由」選「配置」，再開啟連線。

也可在 Safari [一鍵匯入](shadowrocket://config/add/https://raw.githubusercontent.com/kofttlcc/surge-rules/shadowrocket-release/shadowrocket.conf)。若瀏覽器不接受自訂連結，使用上面的手動方式。

若完整版在裝置上編譯緩慢、記憶體不足，或廣告規則造成誤擋，可改用不載入廣告封鎖清單的版本：

```text
https://raw.githubusercontent.com/kofttlcc/surge-rules/shadowrocket-release/shadowrocket-lite.conf
```

這是完整設定檔；原設定的 DNS、分流、重寫不會自動合併，請先保留原設定以便切回。節點與訂閱仍由首頁管理。已有模組可能覆蓋此設定，診斷時一併檢查。

## 預設分流

| 流量 | 策略 |
| --- | --- |
| 現有 `coustom-direct`（包括 Apple 校時及更新相關域名） | DIRECT |
| 區域網路 IP 與私有域名 | DIRECT |
| 上游廣告域名 | REJECT，lite 版不載入 |
| 上游 iCloud 與 Apple 中國大陸可直連清單 | DIRECT |
| 上游代理域名與 Telegram IP | PROXY |
| 上游中國大陸直連域名及中國大陸 IP | DIRECT |
| 其餘流量 | PROXY |

`PROXY` 使用首頁選中的節點，不必另建同名策略組。這是中國大陸網路常用的分流預設；其他環境是否適合直連，需依實際網路調整。Google 直連清單依上游「慎用」說明預設不啟用。`gfw`、`greatfire`、`tld-not-cn`、`google` 仍有獨立產物供進階使用。

DNS 預設跟隨系統。如所在網路有 DNS 污染、解析失敗或節點連線問題，需在裝置實測後調整 DNS。

## 更新及自訂

[Build Shadowrocket rules](https://github.com/kofttlcc/surge-rules/actions/workflows/shadowrocket.yml) 每日 **09:30（UTC+8）** 嘗試更新，也支援 `Run workflow`。GitHub 排程可能延遲，長時間無活動的公開儲存庫也可能被平台停用排程；以 Actions 最近成功紀錄為準。

每次取得上游 `release` 的單一 commit，再轉換並驗證全部清單。資料缺失、為空或出現未知格式即停止，不覆蓋既有版本。`metadata.json` 記錄上游 commit、來源與產物 SHA-256、規則數量。這驗證格式與來源一致性，不保證每條規則分類皆正確。

伺服器更新不等於 iPhone 已更新。請在 Shadowrocket 啟用規則集自動更新，或重新「使用配置／編譯配置」，並檢查更新結果。更新遠端設定可能覆蓋該設定的本機修改。

在原有 `coustom-direct` 每行加一個域名：`example.com` 精確匹配，`.example.com` 後綴匹配。此清單位於前段，可覆蓋其後的廣告及代理規則；只加入確實要直連的域名。提交修改會觸發建置。

## 適配與驗證

- 使用有明確類型的 `ruleset/*.txt`，保留精確域名／後綴區別並去重。
- IPv6 `IP-CIDR6` 轉為 Shadowrocket 的 `IP-CIDR`。
- 區域網路與 Telegram IP 使用 `no-resolve`；中國大陸 IP 允許解析匹配，保留未知域名的 IP 分流。
- 不使用 Surge 的 `PROCESS-NAME`、`RULE-SET,SYSTEM`、`RULE-SET,LAN`、`force-remote-dns` 或 `dns-failed`。
- 沒有 HTTPS 解密、證書、腳本、重寫或節點憑證。

格式參考：[Shadowrocket 社群維護手冊及設定範例](https://github.com/LOWERTOP/Shadowrocket)、[Shadowrocket Telegram 規則集](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/Telegram/Telegram.list)。社群文件並非官方規格。

自動驗證包含格式、CIDR、空資料及未知指令；**不等同在你的 iPhone 上完成連線實測**。匯入後測試區域網路、常用中國大陸網站、海外網站及 Telegram，並在日誌確認命中策略。

本機重建（Python 3.10+，標準函式庫）：

```sh
git clone --depth 1 --branch release https://github.com/Loyalsoldier/surge-rules.git upstream-release
python3 -m unittest discover -s tests -v
python3 scripts/build_shadowrocket.py \
  --source-dir upstream-release \
  --output-dir output \
  --upstream-sha "$(git -C upstream-release rev-parse HEAD)" \
  --repository kofttlcc/surge-rules \
  --custom-direct coustom-direct
```
