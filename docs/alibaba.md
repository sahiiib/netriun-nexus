# Alibaba Cloud connection

Netriun Nexus inventories Alibaba Cloud ECS instances and can submit start, stop, and reboot operations. When an Alibaba account is selected in the portal, it also exposes WUYING Elastic Desktop Service (EDS): region discovery and counts, list and create desktops, start/stop/reboot, renew subscriptions, bind or revoke users, change policy, maintenance mode, Windows remote commands, billing conversion, and list or create convenience accounts. OSS is not queried by this release, so do not grant OSS permissions yet.

## Create a dedicated RAM user

1. Sign in to the Alibaba Cloud RAM console with an account that can manage RAM.
2. Open **Identities > Users**, then select **Create User**.
3. Use a descriptive name such as `netriun-nexus`.
4. Enable **Permanent AccessKey** only. Do not enable console access for this application identity.
5. Copy the AccessKey ID and AccessKey secret immediately. The secret is shown only once.

## Grant the service permissions you enable

1. In RAM, open **Permissions > Policies** and create a custom policy using [alibaba-policy.json](alibaba-policy.json). Remove the EDS statements if this connection only needs ECS.
2. For production, replace the lifecycle statement's wildcard resource with the exact instance ARNs that Netriun may operate, for example `acs:ecs:cn-hangzhou:1234567890123456:instance/i-example`.
3. Return to **Identities > Users**, open `netriun-nexus`, select **Add Permissions**, and attach the custom policy.
4. Do not attach `AdministratorAccess`, `AliyunRAMFullAccess`, or broad product full-access policies to this application user. The EDS API currently documents these operations with `Resource: "*"`, so keep the portal's account and group permissions narrow.

## Connect it to Netriun Nexus

1. Open **Cloud connections > Connect cloud**.
2. Select **Alibaba Cloud**.
3. Enter the AccessKey ID and AccessKey secret.
4. Enter comma-separated region IDs such as `cn-hangzhou, ap-southeast-1`, or leave the field blank to discover all ECS regions available to the credential.
5. Save the connection and select **Sync cloud**. The collector runs asynchronously, so refresh after a few seconds. Connection or permission failures appear on the account card.
6. Select the Alibaba connection from **Active cloud account** in the sidebar. ECS, EDS desktops, and EDS users then become available for that account.

Desktop creation and renewal may incur charges. Netriun Nexus requires an explicit confirmation for both operations. `AutoPay` is off unless selected; an EDS renewal with AutoPay off may create an unpaid order. Subscription renewal only applies to prepaid desktops, and user entitlement changes require the desktop to be running.

If the connection uses an older copy of the RAM policy, replace it with the current [alibaba-policy.json](alibaba-policy.json). The region combobox requires `ecd:DescribeRegions`; the new Manage actions require `ecd:ModifyDesktopsPolicyGroup`, `ecd:SetDesktopMaintenance`, `ecd:RunCommand`, and `ecd:ModifyDesktopChargeType`.

The WUYING user directory uses partition-level endpoints rather than the selected desktop region: `cn-shanghai` for China mainland and `ap-southeast-1` for international regions, including Hong Kong and Europe. Netriun Nexus performs this routing automatically. The desktop page still uses the region selected in the portal.

Use a separate RAM identity or policy for each provider component where practical. Alibaba Cloud Object Storage is named **OSS**, not S3. WUYING uses `ecd` RAM actions, including for the convenience-user API.

Rotate the AccessKey periodically. Netriun Nexus also accepts a static STS security token, but expiring credentials must be replaced before expiration.
