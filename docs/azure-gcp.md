# Azure and Google Cloud connections

Netriun Nexus encrypts all provider credentials before storing them and never
returns them through the API. Use dedicated identities with the narrowest scope
that supports the actions you need.

## Microsoft Azure

Create a Microsoft Entra application/service principal and record its tenant
ID, application (client) ID and client secret. Assign it at the subscription or
resource-group scope:

- `Reader` is sufficient for VM inventory and live details.
- `Virtual Machine Contributor` is required for start, deallocate and restart.

In **Cloud connections**, choose **Microsoft Azure** and enter those values plus
the subscription ID. Region filters are optional; leaving them blank discovers
VMs across the subscription.

Microsoft references:

- [Register an application and service principal](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)
- [Assign Azure roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli)
- [Azure compute roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/compute)

## Google Cloud

Create a dedicated service account in the target project and enable the Compute
Engine API. Grant:

- `roles/compute.viewer` for inventory and live details.
- `roles/compute.instanceAdmin.v1` if Nexus should start, stop and reset VMs.

Create a JSON key for that service account. In **Cloud connections**, choose
**Google Cloud**, enter the project ID and paste the complete JSON key. Region
filters are optional; leaving them blank discovers VMs in every project zone.

Google references:

- [Service accounts overview](https://cloud.google.com/iam/docs/service-account-overview)
- [Compute Engine IAM roles](https://cloud.google.com/compute/docs/access/iam)
- [List VMs across zones](https://cloud.google.com/compute/docs/instances/get-list)

Service-account keys and client secrets are long-lived credentials. Rotate them
regularly and update the connection before disabling the previous credential.

Before saving either provider, use **Test connection** in the connection wizard.
Nexus verifies the identity and required Compute read access, then enables Save.
The verification is valid for ten minutes and is consumed when the connection is saved.
After saving, run **Sync cloud** to populate the inventory.
