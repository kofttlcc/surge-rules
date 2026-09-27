# Shadowrocket iOS 規則發佈

由 [Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules) 的 release
提交 [`d6d0f037e2922d824b858a537a3d3b7229778d93`](https://github.com/Loyalsoldier/surge-rules/commit/d6d0f037e2922d824b858a537a3d3b7229778d93) 轉換。
這個分支是自動生成的產物；請在主分支修改轉換程式或 `coustom-direct`。

## 匯入

先在 Shadowrocket 新增或保留可用節點。在「配置」中以 URL 新增配置，下載後啟用，
再將全局路由設為「配置」，並選擇可用節點。

- [完整配置（含廣告／追蹤攔截）](https://raw.githubusercontent.com/kofttlcc/surge-rules/shadowrocket-release/shadowrocket.conf)
- [精簡配置（不載入 reject 規則）](https://raw.githubusercontent.com/kofttlcc/surge-rules/shadowrocket-release/shadowrocket-lite.conf)

配置使用 Shadowrocket 內建的 `PROXY` 策略，指向目前選擇的代理節點，
不包含節點、訂閱、密碼或解密設定。

## 預設路由

依次為：自訂直連、區域網路、private、reject（完整版本）、iCloud、Apple、
proxy、direct、Telegram IP、中國 IP，最後未匹配流量走代理。
自訂清單中裸域名為精確匹配，前導 `.` 為域名及其子域名匹配。

IPv6 CIDR 轉為 Shadowrocket 的 `IP-CIDR` 語法。區域網路與 Telegram CIDR
使用 `no-resolve`；中國 CIDR 不加此標記，讓未命中域名清單的請求仍可透過
DNS 解析後的中國 IP 直連。`ipv6 = true` 保留 IPv6 路由。

`google`、`gfw`、`greatfire`、`tld-not-cn` 清單亦提供下載，預設配置未啟用。
所有遠端規則 URL 均指向本倉庫的 `shadowrocket-release` 分支。

`metadata.json` 記錄上游提交、每份輸入／輸出的規則數與 SHA-256，
可核對發佈來源。轉換遇到遺漏、空清單或不支援格式時會停止。
上游授權條款見 [LICENSE](LICENSE)。
