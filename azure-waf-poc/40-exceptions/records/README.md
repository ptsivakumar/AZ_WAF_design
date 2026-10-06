# Exception records

One YAML file per exception, named for its exception ID.

| Field | Required | Notes |
|---|---|---|
| `exceptionId` | yes | Also becomes the Azure exemption name |
| `status` | yes | `draft`, `approved`, `expired`, `withdrawn`. Only `approved` deploys |
| `resourceId` | yes | The resource the exemption attaches to |
| `category` | yes | `Mitigated` or `Waiver` — Azure accepts nothing else |
| `exemptFromControls` | yes | Reference IDs from the initiative. **Never leave empty** |
| `businessReason` | yes | Plain language, for the risk register |
| `compensatingControls` | if Mitigated | Enforced by a module precondition |
| `remediationPlan` | if Waiver, or 2nd renewal | Must carry a date |
| `owner`, `securityApprover` | yes | Named people or teams, not "the team" |
| `approvedOn`, `expiryDate` | yes | `expiryDate` is mandatory. There is no permanent exception |
| `renewalCount` | yes | 2 or more without a remediation plan fails the apply |

A record whose `expiryDate` has passed stops being deployed but stays in the
repository as history. That mirrors Azure: at `expiresOn` the exemption object
is preserved for the record but is no longer honoured.
