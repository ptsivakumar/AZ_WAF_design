**Subject:** MAYA – WAF exclusion review (both policies)

Hi Marcin,

Thanks for the policy exports. Attached is the review of both MAYA WAF policies, ahead of the move to the central baseline. Nothing changes on your gateways from this.

The short version: most of it migrates as it is. 28 of your 42 exclusions are already scoped properly, and your team has already mapped the CRS rule groups to DRS – the longest part of the move.

Four things need your input:

1. **The 14 unscoped exclusions** (rows 1–14). Today each one switches off every managed rule for that field. We'd like to narrow them to the rule groups that actually fire. For the sign-in fields we've proposed the scope; for the rest, the Detection run will tell us – you don't need to guess.
2. **Request size and uploads.** Both policies have request body enforcement off and a 512 MB upload limit. Please tell us your largest legitimate request body and upload, so the new policy doesn't start blocking real traffic.
3. **Core and prd.** Policy A has 13 exclusions that Policy B doesn't. Are those waiting to go to prd, or are those features not there?
4. **A risk owner** – one named person who can answer "why is this field excluded?"

Everything is pre-filled with our recommendation. You only need to fill the yellow cells – mostly Agree, Change or Drop. The first tab explains it.

Happy to go through it on a short call if that's easier.

Thanks,
Siva
