# Do this next — written assuming git, pipelines and Terraform are all new

Three parts. **Part 1 needs none of them** and gives you the most valuable result, so start there.

Anything in `code font` is typed exactly as written, except where it says `<like this>`.

---

# PART 1 — Get the evidence (today, ~30 minutes)

No git. No Terraform. No pipeline. Just a browser and one script.

You already have a working WAF_v2 gateway with an App Service behind it, and the App Service
is reachable directly — which means the WAF can be walked around. Proving that, then proving
you closed it, is the single most valuable output of this PoC.

### 1.1 Get the gateway's public IP

Portal → search **Application gateways** → `ccoe-waf-sbx-appgw` → **Overview** → copy the
**Frontend public IP address**.

### 1.2 Run the test — BEFORE changing anything

Open **Git Bash** (comes with Git for Windows) in the folder containing the script:

```bash
chmod +x manual-bypass-test.sh
./manual-bypass-test.sh <the-public-ip> ccoepoctest.azurewebsites.net
```

Expect tests **2, 4 and 5 to return 200**. That is the finding, not a failure.

Test 4 is the important one: a SQL injection reaching the application untouched, because
nothing forces traffic through the WAF.

A file `bypass-manual-<timestamp>.log` appears. **Keep it.**

No Git Bash? In PowerShell:

```powershell
curl.exe -s -o NUL -w "direct clean   %{http_code}`n" "https://ccoepoctest.azurewebsites.net/"
curl.exe -s -o NUL -w "direct attack  %{http_code}`n" "https://ccoepoctest.azurewebsites.net/?id=1%27%20OR%20%271%27=%271"
curl.exe -s -o NUL -w "via gateway    %{http_code}`n" "http://<the-public-ip>/"
```

### 1.3 Close the bypass

Portal → **App Services** → `ccoepoctest` → **Networking** → **Public network access** (or
**Access restrictions**) → **Add rule**:

| Field | Value |
|---|---|
| Name | `allow-appgw` |
| Action | **Allow** |
| Priority | `100` |
| Type | **IPv4** |
| IP address block | `<the-public-ip>/32` |

Then set the **Unmatched rule action** to **Deny**. Save. Wait two minutes.

### 1.4 Run the test again

```bash
./manual-bypass-test.sh <the-public-ip> ccoepoctest.azurewebsites.net
```

Now expect test **1 = 200** and tests **2, 4, 5 = 403**.

**You now have the proof.** Two logs: before and after. Either alone proves nothing. Keep both,
and send them to me — I will write up the finding.

**Leave the restriction on.** Nothing later depends on it being off.

---

# PART 2 — Get the code into the repo (git)

Nothing here changes Azure. Git only moves text files around. Worst case you delete the folder
and start again.

### 2.1 One-time setup

Open Git Bash:

```bash
git --version
git config --global user.name "Siva Kumar"
git config --global user.email "<your Munich Re email>"
```

Use your work email — the repo matches commits to your account by it.

### 2.2 Get a copy of the repo on your laptop

In the browser, open the repo → **Code** (or **Clone**) → copy the **HTTPS** URL.

```bash
cd /c/
git clone <the-url-you-copied> waf
cd waf
```

A browser window opens asking you to sign in. That is normal — it happens once.

You now have `C:\waf` containing the same files as the repo.

### 2.3 Make a branch

**Never work directly on `main`.** A branch is your own copy that nobody else sees until you
ask them to look.

```bash
git checkout -b feat/waf-workload
```

The word after `-b` is just a name. `git branch` shows which one you are on.

### 2.4 Copy the new files in

Unzip `waf-mre-refactor.zip`. Inside is a folder `infrastructure/`.

Copy its contents into `C:\waf\infrastructure\`, **merging** with what is there — Windows will
ask about replacing `data.tf` and `workload.tfvars`; say yes, they are empty.

**Do not replace `versions.tf`.** It is not in the zip, so this will not come up — but if it
somehow does, say no.

After copying you should have:

```
C:\waf\infrastructure\workload\        data.tf  locals.tf  main.tf  outputs.tf  variables.tf  versions.tf
C:\waf\infrastructure\modules\         waf-policy-appgw\  waf-policy-afd\
C:\waf\infrastructure\environments\sbx\  workload.tfvars  workload.tfbackend  bootstrap.*
```

### 2.5 Delete the old folders

These were mine from before you had the repo. They now duplicate and contradict it.

```bash
cd /c/waf
git rm -r --cached 00-bootstrap 10-platform 10-platform-sub 20-modules 30-workload 40-exceptions pipelines 2>/dev/null
rm -rf 00-bootstrap 10-platform 10-platform-sub 20-modules 30-workload 40-exceptions pipelines
rm -f sandbox.tfvars RUNSHEET.md PERSONAL-TENANT.md DEVOPS_REQUEST.md
```

Keep `tests/` — still useful.

### 2.6 Check before you commit

```bash
git status
```

Read the list. You should see new files under `infrastructure/` and deleted files at the root.

```bash
git status --porcelain | grep -E "tfstate|\.terraform"
```

**This must print nothing.** Terraform state files contain secrets in plain text and must never
go into git.

### 2.7 Commit and push

```bash
git add .
git commit -m "feat: Azure WAF workload for sbx"
git push -u origin feat/waf-workload
```

"Commit" = save a labelled snapshot locally. "Push" = send it to the server. Still nothing on
`main`, still nothing in Azure.

### 2.8 Open a Pull Request

Refresh the repo in your browser. A banner offers to create a Pull Request from your branch —
click it. Title it *"Azure WAF workload for sbx"*. Create.

**A PR changes nothing.** It is a request to merge, plus a place for checks to run and for
people to comment.

---

# PART 3 — Let the pipeline run Terraform

### What Terraform is, in two sentences

You describe what you want in `.tf` files. Terraform compares that to what exists in Azure and
makes reality match.

It keeps a file called **state** that records what it built. That is why it must never be told
to manage something it did not create — it would try to build a second one.

### 3.1 Watch the PR checks

Opening the PR should start the pipeline. It will run:

- **validate** — is the code even valid? No Azure access needed.
- **plan** — what *would* change in Azure? **Changes nothing.**

If nothing starts, the pipeline may only trigger on `main`. Tell me and I will adjust the
trigger.

### 3.2 Read the plan

Terraform prints lines like:

```
  # azurerm_linux_web_app.this will be created
  + resource "azurerm_linux_web_app" "this" {
```

- `+` create  ·  `~` change  ·  `-` **destroy**

**Scan for `-` destroy lines.** On a first run there should be none. If there are, stop and
send me the plan.

At the end: `Plan: N to add, 0 to change, 0 to destroy.` Roughly 10–12 to add is right.

### 3.3 Expect it to fail the first time

`terraform validate` has never run on this code — I could only check it against the
documentation. **A first-time error is expected, not a disaster.**

Copy the whole error and send it to me. These are usually one-line fixes, and the fix goes on
the same branch: edit the file, `git add .`, `git commit -m "fix: ..."`, `git push`. The PR
updates itself and the checks re-run.

### 3.4 Before you merge — delete the hand-built gateway

**Important.** `ccoe-waf-sbx-appgw` was created by hand, so Terraform does not know about it.
Terraform will create its own (`ccoe-waf-sbx-appgw-tf`), and you would be paying for two.

So, once Part 1 is finished and both logs are saved:

Portal → **Application gateways** → `ccoe-waf-sbx-appgw` → **Delete**. Also delete the WAF
policy attached to it, and its public IP if one was created for it.

Leave alone: `ccoe-waf-poc-rg`, `ccoe-waf-poc-vnet`, `appgw-subnet`, `ccoepoctest`. Terraform
consumes the first three and ignores the last.

### 3.5 Merge, and let it build

Merge the PR. The pipeline applies. **The Application Gateway takes 15–25 minutes** — normal,
do not interrupt.

### 3.6 Then one change per run

Edit only `environments/sbx/workload.tfvars`, commit, push, merge. One line at a time.

| Run | Change | Gives you |
|---|---|---|
| 1 | nothing — as shipped | Baseline built from code |
| 2 | `lockdown_enabled = true` | Lockdown done by Terraform, not by hand |
| 3 | `waf_mode = "Prevention"` | After tuning |
| 4 | `enable_frontdoor = true` | Pattern A. **Billed per hour** — turn it off after. |

Never skip ahead. The before/after at each step is the result.

---

# If something goes wrong

| What you see | What to do |
|---|---|
| `Author identity unknown` | You skipped 2.1 |
| `Updates were rejected` | `git pull --rebase` then `git push` |
| A `-` destroy line in the plan | **Stop.** Send me the plan. |
| `A resource with this ID already exists` | Something exists that Terraform did not create. Send me the name. |
| Red X on the PR | Click it, copy the error, send it to me |
| Lost / confused | `git status` tells you where you are. Nothing is broken until something is merged. |

**Nothing in Part 2 touches Azure.** Nothing in Part 3 touches Azure until the plan is approved
and merged. You cannot break the environment by making a branch or opening a PR.
